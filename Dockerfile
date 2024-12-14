# Use the official Python image from the Docker Hub
FROM python:3.12-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt requirements.txt

# Install the dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy only necessary files into the container
COPY app.py .
COPY createdb.py .
COPY cryptomath.py .
COPY BlindSig.py .
COPY static/ static/
COPY templates/ templates/

# Create a non-root user and switch to that user
RUN useradd -m myuser
USER myuser

# Expose the port the app runs on
EXPOSE 5000

# Command to run the application
CMD ["python", "app.py"]