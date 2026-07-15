"""
DevSecOps SCA Scanner Utility

Module này thực hiện quét lỗ hổng tĩnh (Software Composition Analysis - SCA)
trên mã nguồn và các dependencies phụ thuộc của chính hệ thống (ví dụ: requirements.txt)
bằng công cụ Trivy.

LƯU Ý: Đây KHÔNG PHẢI là module sinh log quét mạng giả lập hay tương tác
trực tiếp với runtime pipeline của SENTINEL. Mục đích của module này là:
  1. Quét lỗ hổng của chính hệ thống trước khi triển khai (Self-Securing).
  2. Xuất báo cáo dạng JSON lưu trữ tại data/trivy-results.json.
  3. Cung cấp tri thức bảo mật tĩnh để nạp vào Knowledge Graph (Neo4j).
"""

import json
import logging
import os
import subprocess

logger = logging.getLogger(__name__)


class VulnerabilityScanner:
    """Lớp bọc (wrapper) cho bộ quét lỗ hổng Trivy."""

    def __init__(
        self,
        target_dir="/app",
        output_file="data/trivy-results.json",
        sast_output_file="data/bandit-results.json",
    ):
        self.target_dir = target_dir
        self.output_file = output_file
        self.sast_output_file = sast_output_file
        os.makedirs(os.path.dirname(self.output_file), exist_ok=True)

    def run_scan(self):
        """Chạy quét Trivy trên thư mục đích."""
        logger.info(f"Running Trivy scan on {self.target_dir}...")

        try:
            # Kiểm tra xem trivy đã được cài đặt chưa
            subprocess.run(["trivy", "--version"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.warning("Trivy is not installed or not in PATH. Skipping actual scan.")
            self._generate_mock_results()
            return self.output_file

        try:
            # Chạy quét thực tế
            cmd = [
                "trivy",
                "fs",
                self.target_dir,
                "--format",
                "json",
                "--output",
                self.output_file,
                "--scanners",
                "vuln",
                "--skip-dirs",
                "data",
                "--skip-dirs",
                "knowledge_base",
            ]
            subprocess.run(cmd, check=True, capture_output=True)
            logger.info(f"Trivy scan completed. Results saved to {self.output_file}")
            return self.output_file

        except subprocess.CalledProcessError as e:
            logger.error(f"Trivy scan failed: {e.stderr.decode('utf-8')}")
            # Chuyển sang kết quả giả lập nếu có lỗi để giữ pipeline hoạt động
            self._generate_mock_results()
            return self.output_file

    def _generate_mock_results(self):
        """Tạo kết quả giả lập nếu Trivy không khả dụng."""
        mock_data = {
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-XXXX",
                            "PkgName": "mock-pkg",
                            "InstalledVersion": "1.0.0",
                            "Severity": "HIGH",
                            "Description": "Mock vulnerability for testing.",
                            "FixedVersion": "1.0.1",
                        }
                    ],
                }
            ]
        }
        with open(self.output_file, "w") as f:
            json.dump(mock_data, f, indent=2)
        logger.info(f"Generated mock Trivy results at {self.output_file}")

    def run_sast_scan(self):
        """Chạy quét Bandit SAST trên thư mục đích."""
        logger.info(f"Running Bandit SAST scan on {self.target_dir}...")

        try:
            subprocess.run(["bandit", "--version"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.warning("Bandit is not installed or not in PATH. Skipping actual SAST scan.")
            self._generate_mock_sast_results()
            return self.sast_output_file

        try:
            cmd = [
                "bandit",
                "-r",
                self.target_dir,
                "-f",
                "json",
                "-o",
                self.sast_output_file,
                "-ll",
            ]
            subprocess.run(
                cmd, check=False, capture_output=True
            )  # Bandit returns non-zero if issues found
            logger.info(f"Bandit SAST scan completed. Results saved to {self.sast_output_file}")
            return self.sast_output_file
        except Exception as e:
            logger.error(f"Bandit scan failed: {e}")
            self._generate_mock_sast_results()
            return self.sast_output_file

    def _generate_mock_sast_results(self):
        """Tạo kết quả giả lập nếu Bandit không khả dụng."""
        mock_data = {
            "results": [
                {
                    "code": "print('Mock vulnerability')",
                    "filename": "mock_file.py",
                    "issue_confidence": "HIGH",
                    "issue_severity": "MEDIUM",
                    "issue_text": "Mock SAST vulnerability for testing.",
                    "test_id": "B999",
                    "test_name": "mock_test",
                }
            ]
        }
        with open(self.sast_output_file, "w") as f:
            json.dump(mock_data, f, indent=2)
        logger.info(f"Generated mock Bandit results at {self.sast_output_file}")
