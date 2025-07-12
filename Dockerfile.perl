FROM perl:slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Perl dependencies
COPY cpanfile /app/
RUN cpanm --installdeps /app

# Copy application
WORKDIR /app
COPY . .

# Create directories
RUN mkdir -p plugins database templates exec reports

# Set permissions
RUN chmod +x 5ème\ partie\ de\ mon\ tool.perl

# Default execution
ENTRYPOINT ["perl", "5ème partie de mon tool.perl"]
CMD ["-h"]

# Metadata
LABEL org.opencontainers.image.title="WebPredator Web Scanner"
LABEL org.opencontainers.image.version="4.2.0"
LABEL org.opencontainers.image.description="Advanced web vulnerability scanner"
LABEL org.opencontainers.image.authors="Your Name <you@example.com>"
LABEL org.opencontainers.image.licenses="MIT"
