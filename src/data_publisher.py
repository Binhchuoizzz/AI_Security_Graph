"""
Data Publisher: CSV → Redis Streaming Pipeline

MỤC ĐÍCH:
  Đọc dữ liệu từ các file CSV (CICIDS2017, UNSW-NB15, MAWILab) và đẩy
  vào Redis stream, mô phỏng luồng sự kiện thời gian thực.

THIẾT KẾ CHỐNG TRÀN HÀNG ĐỢI (Backpressure):
  CSV lớn (CICIDS2017 = ~2.8M records, ~700MB) không thể nạp hết vào RAM
  hoặc Redis cùng lúc. Publisher sử dụng 3 cơ chế kiểm soát:

  1. Chunked Reading: Đọc CSV theo chunk (mặc định 5,000 dòng/chunk).
     Không bao giờ load toàn bộ file vào RAM.

  2. Redis Queue Depth Limit: Kiểm tra chiều dài queue trước khi đẩy.
     Nếu queue > max_queue_depth (mặc định 10,000) → PAUSE đến khi
     consumer (Tier 1) xử lý bớt. Điều này ngăn Redis OOM.

  3. Timestamp Replay (Tùy chọn): Duy trì khoảng cách thời gian gốc
     giữa các batch để bảo toàn kill-chain chronology.
     - Mode "replay": Giữ đúng timestamp delta gốc (chậm, chính xác)
     - Mode "accelerated": Nén thời gian x10-x100 (nhanh, cho benchmark)
     - Mode "burst": Đẩy hết không delay (tối đa throughput, cho stress test)

USAGE:
  python -m src.data_publisher \\
    --csv data/raw/CICIDS2017.csv \\
    --mode accelerated \\
    --speed 50 \\
    --chunk-size 5000

  Hoặc import và gọi từ main.py:
    from src.data_publisher import DataPublisher
    publisher = DataPublisher(csv_path="data/raw/CICIDS2017.csv")
    publisher.run()
"""
import argparse
import csv
import json
import os
import sys
import time
import yaml
import logging

try:
    import redis
except ImportError:
    redis = None  # Will fail gracefully with clear message

CONFIG_PATH = os.path.join(os.path.dirname(__file__), '..', 'config', 'system_settings.yaml')
logging.basicConfig(level=logging.INFO, format='%(asctime)s [Publisher] %(message)s')
logger = logging.getLogger(__name__)


def load_config():
    with open(CONFIG_PATH, 'r') as f:
        return yaml.safe_load(f)


class DataPublisher:
    """
    Đẩy dữ liệu CSV vào Redis stream với backpressure control.

    Supported CSV formats:
    - CICIDS2017: 78 features + Label
    - UNSW-NB15: 49 features + label
    - MAWILab: Custom format

    Key fields được giữ nguyên tên gốc từ CSV header.
    Mỗi record được serialize thành JSON string trước khi push vào Redis.
    """
    def __init__(self, csv_path: str, mode: str = "accelerated",
                 speed_multiplier: float = 50.0,
                 chunk_size: int = 5000,
                 max_queue_depth: int = 10000):
        """
        Args:
            csv_path: Đường dẫn tới file CSV.
            mode: "replay" | "accelerated" | "burst"
                - replay: Giữ đúng timestamp spacing gốc
                - accelerated: Nén thời gian x speed_multiplier
                - burst: Đẩy tối đa không delay
            speed_multiplier: Hệ số tăng tốc (chỉ dùng khi mode=accelerated).
                50.0 = nhanh gấp 50 lần thực tế.
            chunk_size: Số dòng đọc mỗi lần từ CSV.
            max_queue_depth: Giới hạn queue Redis. Publisher PAUSE khi queue vượt ngưỡng.
        """
        if redis is None:
            raise ImportError(
                "redis package not installed. Run: pip install redis"
            )

        self.csv_path = csv_path
        self.mode = mode
        self.speed_multiplier = speed_multiplier
        self.chunk_size = chunk_size
        self.max_queue_depth = max_queue_depth

        config = load_config()
        redis_config = config.get('redis', {})
        self.queue_name = redis_config.get('queue_name', 'security_logs_stream')

        self.redis_client = redis.Redis.from_url(
            redis_config.get('url', 'redis://localhost:6379/0'),
            decode_responses=True
        )

        # Stats
        self.total_published = 0
        self.total_paused_seconds = 0
        self.start_time = None

    def _detect_timestamp_column(self, headers: list) -> str:
        """Tự động phát hiện cột timestamp từ CSV header."""
        timestamp_candidates = [
            'Timestamp', 'timestamp', 'Flow Duration', 'flow_duration',
            'stime', 'ltime', 'time', 'Time'
        ]
        for col in timestamp_candidates:
            if col in headers:
                return col
        return None

    def _detect_label_column(self, headers: list) -> str:
        """Tự động phát hiện cột label từ CSV header."""
        label_candidates = [
            ' Label', 'Label', 'label', 'attack_cat', 'Attack',
            'classification', 'class'
        ]
        for col in label_candidates:
            if col in headers:
                return col
        return None

    def _wait_for_backpressure(self):
        """
        BACKPRESSURE CONTROL: Pause khi queue Redis quá đầy.
        Ngăn chặn Redis OOM và cho phép consumer (Tier 1) bắt kịp.
        """
        while True:
            queue_len = self.redis_client.llen(self.queue_name)
            if queue_len < self.max_queue_depth:
                return
            logger.warning(
                f"⏸  Backpressure: queue={queue_len}/{self.max_queue_depth}. "
                f"Waiting for Tier 1 to consume..."
            )
            time.sleep(1.0)
            self.total_paused_seconds += 1.0

    def _calculate_delay(self, prev_ts: float, curr_ts: float) -> float:
        """
        Tính delay giữa 2 records dựa trên mode:
        - replay: Giữ nguyên khoảng cách thời gian gốc
        - accelerated: Nén time x speed_multiplier
        - burst: 0 delay
        """
        if self.mode == "burst":
            return 0.0

        if prev_ts is None or curr_ts is None:
            return 0.01  # Default minimal delay

        delta = abs(curr_ts - prev_ts)

        if self.mode == "replay":
            return min(delta, 5.0)  # Cap ở 5 giây tránh chờ quá lâu

        if self.mode == "accelerated":
            compressed = delta / self.speed_multiplier
            return min(compressed, 1.0)  # Cap ở 1 giây

        return 0.01

    def _parse_timestamp(self, value: str) -> float:
        """Thử parse timestamp từ nhiều format khác nhau."""
        if not value or value.strip() == '':
            return None

        # Thử parse dạng số (epoch hoặc duration)
        try:
            return float(value.strip())
        except (ValueError, TypeError):
            pass

        # Thử parse dạng date/time chuẩn
        formats = [
            "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M",
            "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f",
        ]
        for fmt in formats:
            try:
                import datetime
                dt = datetime.datetime.strptime(value.strip(), fmt)
                return dt.timestamp()
            except ValueError:
                continue

        return None

    def _clean_row(self, row: dict) -> dict:
        """Dọn dẹp dữ liệu trước khi publish."""
        cleaned = {}
        for key, value in row.items():
            # Strip whitespace từ cả key và value
            clean_key = key.strip() if key else key
            clean_value = value.strip() if isinstance(value, str) else value

            # Skip empty keys
            if not clean_key:
                continue

            # Thử convert số
            if isinstance(clean_value, str):
                try:
                    if '.' in clean_value:
                        clean_value = float(clean_value)
                    else:
                        clean_value = int(clean_value)
                except (ValueError, TypeError):
                    pass

            cleaned[clean_key] = clean_value

        return cleaned

    def run(self):
        """
        Main loop: Đọc CSV → Clean → Backpressure Check → Push Redis.
        """
        if not os.path.exists(self.csv_path):
            logger.error(f"CSV file not found: {self.csv_path}")
            return

        self.start_time = time.time()
        file_size_mb = os.path.getsize(self.csv_path) / (1024 * 1024)
        logger.info(f"📂 Opening: {self.csv_path} ({file_size_mb:.1f} MB)")
        logger.info(f"⚙  Mode: {self.mode}, Speed: x{self.speed_multiplier}, "
                     f"Chunk: {self.chunk_size}, Max Queue: {self.max_queue_depth}")

        timestamp_col = None
        label_col = None
        prev_timestamp = None

        try:
            with open(self.csv_path, 'r', encoding='utf-8', errors='replace') as f:
                reader = csv.DictReader(f)
                headers = reader.fieldnames or []

                timestamp_col = self._detect_timestamp_column(headers)
                label_col = self._detect_label_column(headers)

                logger.info(f"📋 Headers: {len(headers)} columns")
                logger.info(f"🕐 Timestamp column: {timestamp_col or 'NOT FOUND'}")
                logger.info(f"🏷  Label column: {label_col or 'NOT FOUND'}")

                chunk_buffer = []

                for row in reader:
                    # Clean row
                    cleaned = self._clean_row(row)
                    if not cleaned:
                        continue

                    # Extract timestamp for replay timing
                    curr_timestamp = None
                    if timestamp_col and timestamp_col in cleaned:
                        curr_timestamp = self._parse_timestamp(
                            str(cleaned.get(timestamp_col, ''))
                        )

                    # Add metadata
                    cleaned['_publisher_seq'] = self.total_published
                    cleaned['_publish_time'] = time.time()

                    chunk_buffer.append((cleaned, curr_timestamp))

                    if len(chunk_buffer) >= self.chunk_size:
                        self._publish_chunk(chunk_buffer, prev_timestamp)
                        if chunk_buffer:
                            prev_timestamp = chunk_buffer[-1][1]
                        chunk_buffer = []

                # Flush remaining
                if chunk_buffer:
                    self._publish_chunk(chunk_buffer, prev_timestamp)

        except Exception as e:
            logger.error(f"❌ Error reading CSV: {e}")
            raise

        elapsed = time.time() - self.start_time
        logger.info(
            f"✅ Completed: {self.total_published} records in {elapsed:.1f}s "
            f"({self.total_published / max(elapsed, 0.1):.0f} rec/s). "
            f"Paused: {self.total_paused_seconds:.1f}s due to backpressure."
        )

    def _publish_chunk(self, chunk: list, prev_ts: float):
        """Publish một chunk records vào Redis với backpressure."""
        # Backpressure check TRƯỚC khi push
        self._wait_for_backpressure()

        pipeline = self.redis_client.pipeline()

        for record, curr_ts in chunk:
            # Timestamp replay delay (chỉ giữa các chunks, không mỗi record)
            serialized = json.dumps(record, default=str)
            pipeline.rpush(self.queue_name, serialized)
            self.total_published += 1

        pipeline.execute()

        # Apply timing delay SAU khi push chunk
        if chunk and self.mode != "burst":
            first_ts = chunk[0][1]
            last_ts = chunk[-1][1]
            if first_ts and last_ts:
                delay = self._calculate_delay(prev_ts or first_ts, last_ts)
                if delay > 0:
                    time.sleep(delay)

        if self.total_published % (self.chunk_size * 5) == 0:
            queue_len = self.redis_client.llen(self.queue_name)
            elapsed = time.time() - self.start_time
            logger.info(
                f"📊 Published: {self.total_published:,} | "
                f"Queue: {queue_len:,}/{self.max_queue_depth:,} | "
                f"Rate: {self.total_published / max(elapsed, 0.1):.0f} rec/s"
            )

    def get_stats(self) -> dict:
        """Trả về thống kê cho MLflow logging."""
        elapsed = time.time() - (self.start_time or time.time())
        return {
            'total_published': self.total_published,
            'elapsed_seconds': elapsed,
            'throughput_rps': self.total_published / max(elapsed, 0.1),
            'paused_seconds': self.total_paused_seconds,
            'mode': self.mode,
            'speed_multiplier': self.speed_multiplier,
            'csv_path': self.csv_path
        }


def main():
    parser = argparse.ArgumentParser(
        description='SENTINEL Data Publisher: CSV → Redis Stream'
    )
    parser.add_argument(
        '--csv', required=True,
        help='Path to CSV dataset file'
    )
    parser.add_argument(
        '--mode', choices=['replay', 'accelerated', 'burst'],
        default='accelerated',
        help='Timing mode: replay (real-time), accelerated (compressed), burst (max speed)'
    )
    parser.add_argument(
        '--speed', type=float, default=50.0,
        help='Speed multiplier for accelerated mode (default: 50x)'
    )
    parser.add_argument(
        '--chunk-size', type=int, default=5000,
        help='Number of rows per read chunk (default: 5000)'
    )
    parser.add_argument(
        '--max-queue', type=int, default=10000,
        help='Max Redis queue depth before backpressure pause (default: 10000)'
    )

    args = parser.parse_args()

    publisher = DataPublisher(
        csv_path=args.csv,
        mode=args.mode,
        speed_multiplier=args.speed,
        chunk_size=args.chunk_size,
        max_queue_depth=args.max_queue
    )

    try:
        publisher.run()
    except KeyboardInterrupt:
        stats = publisher.get_stats()
        logger.info(f"⛔ Interrupted. Stats: {json.dumps(stats, indent=2)}")
        sys.exit(0)


if __name__ == '__main__':
    main()
