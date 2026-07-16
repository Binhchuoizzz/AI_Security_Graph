#!/bin/bash

# Thư mục chứa các model tải về
MODELS_DIR="/home/binhchuoiz/text-generation-webui/user_data/models"

# Kiểm tra nếu không truyền tham số
if [ -z "$1" ]; then
    echo "=========================================="
    echo "🔧 CÔNG CỤ CHUYỂN ĐỔI MODEL LLM SENTINEL"
    echo "=========================================="
    echo "Sử dụng: ./scripts/switch_model.sh <số_thứ_tự_hoặc_tên_file>"
    echo ""
    echo "📦 Các model đang có sẵn trong thư mục của bạn:"
    ls -1 "$MODELS_DIR" | grep -E "\.gguf$" | cat -n
    echo ""
    echo "💡 Ví dụ chạy: ./scripts/switch_model.sh 2"
    exit 1
fi

MODEL_TARGET="$1"

# Kiểm tra nếu tham số truyền vào là 1 con số (chọn từ menu)
if [[ "$MODEL_TARGET" =~ ^[0-9]+$ ]]; then
    MODEL_FILE=$(ls -1 "$MODELS_DIR" | grep -E "\.gguf$" | sed -n "${MODEL_TARGET}p")
    if [ -z "$MODEL_FILE" ]; then
        echo "[!] LỖI: Không tìm thấy model ở số thứ tự: $MODEL_TARGET"
        exit 1
    fi
else
    # Nếu truyền tên file trực tiếp
    MODEL_FILE="$MODEL_TARGET"
    if [ ! -f "$MODELS_DIR/$MODEL_FILE" ]; then
        echo "[!] LỖI: Không tồn tại file: $MODELS_DIR/$MODEL_FILE"
        exit 1
    fi
fi

echo "[*] Đang cấu hình chuyển sang model: $MODEL_FILE"

# Cập nhật file .env (thay thế dòng LLM_MODEL_FILE)
if grep -q "^LLM_MODEL_FILE=" .env; then
    sed -i "s|^LLM_MODEL_FILE=.*|LLM_MODEL_FILE=$MODEL_FILE|g" .env
else
    echo "LLM_MODEL_FILE=$MODEL_FILE" >> .env
fi

# Tự động điều chỉnh Context Size để chống tràn VRAM (OOM) cho các model 13B (không có GQA)
if [[ "$MODEL_FILE" == *"13B"* ]]; then
    CTX_SIZE=8192
else
    CTX_SIZE=16384
fi

if grep -q "^LLAMA_ARG_CTX_SIZE=" .env; then
    sed -i "s|^LLAMA_ARG_CTX_SIZE=.*|LLAMA_ARG_CTX_SIZE=$CTX_SIZE|g" .env
else
    echo "LLAMA_ARG_CTX_SIZE=$CTX_SIZE" >> .env
fi

echo "[*] Đang gửi lệnh khởi động lại container sentinel_llm..."
# Dùng docker-compose up -d để recreate container llm với biến môi trường mới
export LLM_MODEL_FILE="$MODEL_FILE"
docker-compose up -d --force-recreate llm

echo "------------------------------------------"
echo "[+] Đã cấu hình sang model: $MODEL_FILE"
echo "[*] Đang đợi model nạp lên VRAM (khoảng 15-30 giây)..."

# Đợi server báo healthy qua healthcheck
for i in {1..30}; do
    LOADED_MODEL=$(curl -s http://localhost:5000/v1/models | grep -o '"id":"[^"]*"' | cut -d'"' -f4)
    if [ ! -z "$LOADED_MODEL" ]; then
        echo "------------------------------------------"
        echo "🚀 HOÀN TẤT! Model đang chạy TRÊN VRAM ngay lúc này là:"
        echo "   👉 $LOADED_MODEL"
        echo "------------------------------------------"
        break
    fi
    sleep 2
done
