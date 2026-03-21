# Base Image
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Install system dependencies
# libgomp1 is critical for scikit-learn (OpenMP)
# curl is for internal health checks
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire project
COPY . .

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Expose ports
EXPOSE 80 8501

# Start script
RUN chmod +x start.sh
CMD ["./start.sh"]
