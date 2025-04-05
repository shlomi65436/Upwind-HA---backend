FROM ubuntu:latest

# Install required system dependencies
RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-venv \
    tcpdump strace inotify-tools wireshark-common tshark \
    net-tools iproute2 iptables dnsutils netcat-openbsd \
    lsof curl wget nmap && \
    rm -rf /var/lib/apt/lists/*

# Create a virtual environment
RUN python3 -m venv /venv
ENV PATH="/venv/bin:$PATH"

# Install Python packages inside the virtual environment
RUN pip install --no-cache-dir psutil watchdog pyshark scapy

# Set working directory
WORKDIR /sandbox

# Copy the monitoring script
COPY malware_monitor.py .

# Set entrypoint
ENTRYPOINT ["python", "malware_monitor.py"]