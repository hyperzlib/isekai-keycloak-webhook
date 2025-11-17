from http.server import BaseHTTPRequestHandler, HTTPServer
import argparse
import hashlib

global signature_secret

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    @staticmethod
    def check_signature(signature: str, data: bytes) -> bool:
        global signature_secret
        data_sha256 = hashlib.sha256(data).hexdigest()
        print("Data SHA256:", data_sha256)
        payload = (signature_secret + data_sha256).encode('ascii')
        expected_signature = hashlib.sha256(payload).hexdigest()
        return signature == expected_signature

    def do_GET(self):
        print(f"Received GET request:\nPath: {self.path}\nHeaders:\n{self.headers}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"GET request received")

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        print(f"Received POST request:\nPath: {self.path}\nHeaders:\n{self.headers}\nBody:\n{post_data.decode('utf-8')}")

        try:
            global signature_secret
            if signature_secret:
                signature = self.headers.get('X-Signature', '')
                if not signature:
                    print("[ ] No signature provided!")

                    if not self.check_signature(signature, post_data):
                        print("[x] Invalid signature!")
                    else:
                        print("[√] Signature valid.")
            else:
                print("Skipping signature validation (no secret provided).")
        except Exception as e:
            print("[x] Error during signature validation:", str(e))

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"POST request received")

def run(handler_class=SimpleHTTPRequestHandler, port: int = 8234, secret: str = None):
    server_address = ('', port)
    httpd = HTTPServer(server_address, handler_class)

    print(f"Starting server on port {port}...")

    # handle KeyboardInterrupt to gracefully shutdown the server
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        httpd.server_close()
        print("Server stopped.")

if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(description="Simple HTTP Server to receive webhooks")
    arg_parser.add_argument("--port", type=int, default=8234, help="Port to listen on (default: 8234)")
    arg_parser.add_argument("--secret", type=str, help="Secret for validating incoming requests signatures")

    args = arg_parser.parse_args()

    signature_secret = args.secret

    run(port=args.port)