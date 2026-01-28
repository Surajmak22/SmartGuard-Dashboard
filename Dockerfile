# Base Image
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Install system dependencies (if any)
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install Dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire project
COPY . .

# Expose the standard Streamlit port
EXPOSE 8501

# Healthcheck for Railway/Render
HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health || exit 1

# Entry Point
CMD ["streamlit", "run", "src/dashboard/main_app.py", "--server.port=8501", "--server.address=0.0.0.0", "--theme.base=dark"]
