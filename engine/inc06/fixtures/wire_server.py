"""Legacy pricing server with an undocumented binary protocol (opaque to the port).
Frame: 2-byte length, then body. Request body: header D7 01, then TLVs (1-byte tag, 1-byte length):
1 qty u32, 2 price_cents u32, 3 region ascii, 4 tier ascii, 5 memo ascii.
Response body: header D7 81, then 0x11 total_cents u32, 0x12 approval u8, 0x13 seq u32, 0x14 memo ascii."""
import socket, socketserver, threading
FEE = {"CA": 150, "TX": 0, "NY": 300, "OR": 75}; TIER = {"A": 100, "B": 90, "C": 75}
SEQ = [1000]
def tlv(tag, raw): return bytes([tag, len(raw)]) + raw
def parse(body):
    i, out = 2, {}
    while i < len(body): t, n = body[i], body[i + 1]; out[t] = body[i + 2:i + 2 + n]; i += 2 + n
    return out
def respond(body, mode):
    f = parse(body); qty, price = int.from_bytes(f[1], "big"), int.from_bytes(f[2], "big")
    region, tier, memo = f[3].decode(), f[4].decode(), f[5]
    if mode in ("constant", "constant_b"):
        total, appr = (4242, 0) if mode == "constant" else (777, 1); memo = b"X" if mode == "constant" else b"YY"
    else: total = qty * price * TIER.get(tier, 100) // 100 + FEE.get(region, 0); appr = 1 if total >= 1_000_000 else 0
    SEQ[0] += 1
    return b"\xD7\x81" + tlv(0x11, total.to_bytes(4, "big")) + tlv(0x12, bytes([appr])) + tlv(0x13, SEQ[0].to_bytes(4, "big")) + tlv(0x14, memo)
def make_request(q):
    return b"\xD7\x01" + tlv(1, q["qty"].to_bytes(4, "big")) + tlv(2, q["price"].to_bytes(4, "big")) + tlv(3, q["region"].encode()) + tlv(4, q["tier"].encode()) + tlv(5, q["memo"].encode())
def serve(port, mode="real"):
    class H(socketserver.BaseRequestHandler):
        def handle(self):
            n = int.from_bytes(self.request.recv(2), "big"); b = b""
            while len(b) < n: b += self.request.recv(n - len(b))
            r = respond(b, mode); self.request.sendall(len(r).to_bytes(2, "big") + r)
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    s = socketserver.ThreadingTCPServer(("127.0.0.1", port), H); threading.Thread(target=s.serve_forever, daemon=True).start(); return s
def tap(port, rng, n=40):
    """A passive wire tap: hex request/response pairs from ordinary traffic."""
    dom = {"qty": [1, 3, 5, 8, 12, 20], "price": [500, 1250, 1999, 4000], "region": list(FEE), "tier": list(TIER), "memo": ["m-alpha", "m-bravo", "m-charlie"]}
    lines = []
    for _ in range(n):
        q = {k: rng.choice(v) for k, v in dom.items()}; req = make_request(q)
        s = socket.create_connection(("127.0.0.1", port)); s.sendall(len(req).to_bytes(2, "big") + req)
        m = int.from_bytes(s.recv(2), "big"); res = b""
        while len(res) < m: res += s.recv(m - len(res))
        s.close(); lines.append(f"REQ {req.hex()} RES {res.hex()}")
    return lines
