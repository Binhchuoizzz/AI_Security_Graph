#!/bin/bash
# ==============================================================================
# SENTINEL Model Switcher Script
# Tự động thay đổi model trong .env và restart container llm
# ==============================================================================

ENV_FILE=".env"
GEMMA_MODEL="gemma-2-9b-it-Q6_K.gguf"
LLAMA_MODEL="Meta-Llama-3-8B-Instruct-Q5_K_M.gguf"

if [ ! -f "$ENV_FILE" ]; then
    echo "[!] ERROR: Không tìm thấy file .env ở thư mục hiện tại!"
    exit 1
fi

show_usage() {
    echo "Sử dụng: $0 [gemma | llama | <tên_file_model.gguf>]"
    echo "  gemma: Switch sang Google Gemma 2 9B IT (Agent suy luận mặc định)"
    echo "  llama: Switch sang Meta Llama 3 8B Instruct (AI Trọng tài đánh giá)"
}

if [ -z "$1" ]; then
    show_usage
    exit 1
fi

TARGET_MODEL=""
if [ "$1" == "gemma" ]; then
    TARGET_MODEL="$GEMMA_MODEL"
elif [ "$1" == "llama" ]; then
    TARGET_MODEL="$LLAMA_MODEL"
else
    TARGET_MODEL="$1"
fi

echo "[*] Đang chuyển đổi LLM sang model: $TARGET_MODEL..."

# Thay thế dòng LLM_MODEL_FILE trong .env bằng regex
if [[ "$OSTYPE" == "darwin"* ]]; then
    # MacOS syntax
    sed -i '' "s/LLM_MODEL_FILE=.*/LLM_MODEL_FILE=$TARGET_MODEL/g" "$ENV_FILE"
else
    # Linux syntax
    sed -i "s/LLM_MODEL_FILE=.*/LLM_MODEL_FILE=$TARGET_MODEL/g" "$ENV_FILE"
fi

echo "[+] Đã cập nhật file .env thành công."
echo "[*] Đang khởi động lại container sentinel_llm..."

docker-compose up -d llm

echo "[*] Chờ container llm chuyển sang trạng thái healthy..."
while true; do
    STATUS=$(docker inspect --format='{{json .State.Health.Status}}' sentinel_llm 2>/dev/null)
    if [ "$STATUS" == "\"healthy\"" ]; then
        echo -e "\n[+] Container sentinel_llm đã ONLINE và HEALTHY!"
        break
    elif [ "$STATUS" == "\"unhealthy\"" ]; then
        echo -e "\n[!] ERROR: Container sentinel_llm gặp lỗi khi load model!"
        exit 1
    else
        echo -n "."
        sleep 3
    fi
done

echo "[+] Done! Hệ thống đã được cấu hình với model: $TARGET_MODEL."
