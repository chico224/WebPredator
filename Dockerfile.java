FROM maven:3.9.5-openjdk-17-slim as builder

WORKDIR /app

# Copy project files
COPY pom.xml .
COPY src src

# Build the application
RUN mvn clean package -DskipTests

# -----------------------------
# Stage 2: runtime
# -----------------------------
FROM openjdk:17-slim

WORKDIR /app

# Copy the JAR from builder
COPY --from=builder /app/target/webpredator-*.jar app.jar

# Copy configuration files
COPY src/main/resources/config.yaml .
COPY src/main/resources/log4j2.xml .

# Create directories
RUN mkdir -p plugins database templates exec reports logs

# Set permissions
RUN chmod +x app.jar

# Default execution
ENTRYPOINT ["java", "-Djava.security.egd=file:/dev/./urandom", "-jar", "app.jar"]

# Metadata
LABEL org.opencontainers.image.title="WebPredator Security Platform"
LABEL org.opencontainers.image.version="4.2.0"
LABEL org.opencontainers.image.description="Next-generation web application security solution"
LABEL org.opencontainers.image.authors="Your Name <you@example.com>"
LABEL org.opencontainers.image.licenses="Commercial"

# Expose ports
EXPOSE 8080 8443
