import socket
import threading
import time

def ftp_listener():
    # Simple listener on port 2121 to reliably accept a connection
    # and read the USER/PASS commands
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 2121))
    server.listen(1)
    try:
        conn, addr = server.accept()
        conn.sendall(b"220 Minimal FTP Server\r\n")
        data = conn.recv(1024)
        data = conn.recv(1024)
        conn.close()
    except Exception:
        pass
    finally:
        server.close()

def send_ftp_creds(port):
    print(f"Attempting to send FTP creds to 127.0.0.1:{port}...")
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(2)
        client.connect(("127.0.0.1", port))
        client.sendall(b"USER testuser\r\n")
        client.sendall(b"PASS testpassword123\r\n")
        client.close()
        print(f"Successfully sent FTP creds to port {port}.")
    except Exception as e:
        print(f"Failed on port {port}: {e} (Expected if no listener)")

if __name__ == "__main__":
    print("Starting FTP Cleartext Simulation")
    
    # Try the default FTP port 21
    send_ftp_creds(21)
    
    # Try reliable non-privileged port 2121
    # Start listener thread
    t = threading.Thread(target=ftp_listener)
    t.daemon = True
    t.start()
    
    # Let listener start up
    time.sleep(1)
    
    send_ftp_creds(2121)
    
    print("FTP Cleartext Simulation Complete.")
