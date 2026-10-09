import http.server
import socketserver
import argparse
import sys
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

class EchoHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        logging.info(f"Received GET request for path: {self.path} from {self.client_address}")
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(f"Echo GET: {self.path}".encode('utf-8'))

    def do_POST(self):
        logging.info(f"Received POST request for path: {self.path} from {self.client_address}")
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(f"Echo POST: {self.path}".encode('utf-8'))

def run_server(port=8080):
    handler = EchoHandler
    try:
        with socketserver.TCPServer(("0.0.0.0", port), handler) as httpd:
            logging.info(f"Serving HTTP on 0.0.0.0 port {port} (http://0.0.0.0:{port}/)")
            httpd.serve_forever()
    except KeyboardInterrupt:
        logging.info("Server stopped.")
    except Exception as e:
        logging.error(f"Error starting server: {e}")
        sys.exit(1)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Local Web Server for testing.")
    parser.add_argument('-p', '--port', type=int, default=8080, help='Port to listen on (default: 8080)')
    args = parser.parse_args()
    run_server(args.port)
