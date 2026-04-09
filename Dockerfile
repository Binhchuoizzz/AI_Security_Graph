FROM python:3.10-slim

WORKDIR /app

# Install dependencies needed generally
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all code
COPY . .

# Expose Streamlit port
EXPOSE 8501

# Run the Streamlit app specifically pointing to src/ui/app.py
ENTRYPOINT ["streamlit", "run", "src/ui/app.py", "--server.port=8501", "--server.address=0.0.0.0"]
