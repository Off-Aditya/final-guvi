FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy only necessary files
COPY honeypot_api.py .
COPY model/phising_model ./model/phising_model
COPY model/phising_tokenizer ./model/phising_tokenizer

# Create directory structure for model if needed by code
# The code expects "model/phising_model" relative path

# Expose the port (Hugging Face Spaces uses 7860)
EXPOSE 7860

# Run the application with Gunicorn
CMD ["gunicorn", "-b", "0.0.0.0:7860", "honeypot_api:app", "--timeout", "120"]
