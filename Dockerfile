FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    openjdk-21-jdk \
    curl \
    unzip \
    php-cli \
    && rm -rf /var/lib/apt/lists/*

RUN curl -L "https://github.com/joernio/joern/releases/latest/download/joern-cli.zip" -o /tmp/joern-cli.zip && \
    unzip /tmp/joern-cli.zip -d /opt && \
    mv /opt/joern-cli /opt/joern && \
    rm /tmp/joern-cli.zip

ENV PATH="/opt/joern:${PATH}"

WORKDIR /app
EXPOSE 9000

ENTRYPOINT ["joern"]