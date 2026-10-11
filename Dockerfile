FROM python:3.12-slim

WORKDIR /app

# Install dependencies first so they cache across source changes.
COPY pyproject.toml README.md ./
COPY vigil ./vigil
COPY tools ./tools
RUN pip install --no-cache-dir ".[api]"

# Bundle a sample capture so the container has something to show out of the box.
RUN python tools/make_sample_pcap.py /app/sample.pcap

EXPOSE 8089

# Default: serve the dashboard replaying the sample capture in a loop.
# For live capture instead, run with --iface and give the container
# NET_RAW plus host networking (see docker-compose.yml).
CMD ["vigil", "serve", "--pcap", "/app/sample.pcap", "--host", "0.0.0.0", "--port", "8089"]
