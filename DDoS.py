import psutil
import socket
from collections import defaultdict
import time

def monitor_network():
    # Dictionary to track IP addresses and their request counts
    ip_counts = defaultdict(int)
    
    # Monitor server resources
    cpu_usage = psutil.cpu_percent(interval=1)
    memory_usage = psutil.virtual_memory().percent
    net_io = psutil.net_io_counters()
    
    print(f"CPU Usage: {cpu_usage}%")
    print(f"Memory Usage: {memory_usage}%")
    print(f"Network I/O: Sent {net_io.bytes_sent/1024/1024:.2f} MB, Received {net_io.bytes_recv/1024/1024:.2f} MB")

    # Create a socket for capturing traffic
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.bind(("0.0.0.0", 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        
        start_time = time.time()
        while time.time() - start_time < 60:  # Monitor for 1 minute
            data = s.recvfrom(65565)
            ip_header = data[0][0:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            
            source_ip = socket.inet_ntoa(iph[8])
            ip_counts[source_ip] += 1

        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        
        # Check for suspicious activity
        for ip, count in ip_counts.items():
            if count > 100:  # Arbitrary threshold for high number of requests
                print(f"Suspicious activity detected from IP: {ip} with {count} requests in a minute")

    except socket.error as e:
        print(f"Socket Error: {e}")
    finally:
        s.close()

if __name__ == "__main__":
    monitor_network()
