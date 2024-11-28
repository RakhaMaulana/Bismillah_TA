# Gunakan image dasar Python 3.12
FROM python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Salin file requirements.txt dan install dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Salin seluruh kode aplikasi ke dalam container
COPY . /app/

# Install pyOpenSSL
RUN pip install pyOpenSSL

# Buat sertifikat SSL self-signed
RUN python generate_ssl_cert.py

# Expose port 5000
EXPOSE 5000

# Jalankan aplikasi Flask
CMD ["python", "app.py"]