# Use an official Ubuntu image as the base
FROM ubuntu:latest

# Install necessary packages (GCC, make, gdb, vim, etc.)
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    gdb \
    make \
    vim \
    git

# Set the working directory
WORKDIR /app

# Expose ports if necessary (optional, e.g., for debugging)
EXPOSE 8080

# Set default command to keep container running in interactive mode
CMD ["bash"]
