import http.server, socketserver, sys, os, threading
LOG=sys.argv[2]; CMD=sys.argv[3]; lock=threading.Lock()
class H(http.server.SimpleHTTPRequestHandler):
    extensions_map={**http.server.SimpleHTTPRequestHandler.extensions_map,'.wasm':'application/wasm','.js':'text/javascript','.webmanifest':'application/manifest+json'}
    def do_POST(self):
        n=int(self.headers.get('Content-Length',0)); b=self.rfile.read(n)
        open(LOG,'ab').write(b+b'\n'); self.send_response(204); self.end_headers()
    def do_GET(self):
        if self.path.startswith('/cmd'):
            who=self.path.split('who=')[-1] if 'who=' in self.path else 'a'
            with lock:
                f=CMD+'.'+who
                lines=open(f).read().splitlines() if os.path.exists(f) else []
                out=lines[0] if lines else ''
                open(f,'w').write('\n'.join(lines[1:])+('\n' if len(lines)>1 else ''))
            body=out.encode(); self.send_response(200); self.send_header('Content-Type','text/plain'); self.send_header('Content-Length',str(len(body))); self.send_header('Cache-Control','no-store'); self.end_headers(); self.wfile.write(body); return
        super().do_GET()
    def end_headers(self):
        self.send_header('Cache-Control','no-store'); super().end_headers()
    def log_message(self,*a): pass
socketserver.TCPServer.allow_reuse_address=True
# A cold load requests many runtime modules at once; the default backlog of 5
# could reset one and leave the page blank with no error.
socketserver.TCPServer.request_queue_size=128
with socketserver.ThreadingTCPServer(('127.0.0.1',int(sys.argv[1])),H) as s: s.serve_forever()
