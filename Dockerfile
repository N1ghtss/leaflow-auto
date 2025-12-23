# Use official Python runtime as base image
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Configure apt to use Tsinghua mirror
RUN sed -i 's/deb.debian.org/mirrors.tuna.tsinghua.edu.cn/g' /etc/apt/sources.list.d/debian.sources \
    && sed -i 's/security.debian.org/mirrors.tuna.tsinghua.edu.cn/g' /etc/apt/sources.list.d/debian.sources

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY requirements.txt .
COPY app.py .

# Install Python dependencies using Tsinghua mirror
RUN pip install --no-cache-dir -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

# Create config directory
RUN mkdir -p /app/config

# Set environment variable defaults
ENV PORT=8181
ENV ADMIN_USERNAME=admin
ENV ADMIN_PASSWORD=admin123
ENV JWT_SECRET_KEY=""
ENV CONFIG_DIR=/app/config

# Expose port
EXPOSE 8181

# Start control panel
CMD ["python3", "app.py"]
