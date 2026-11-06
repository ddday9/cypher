#!/usr/bin/env python3
"""TCP proxy that imitates the TSPU "freeze": once LIMIT bytes went from the
server to the client on one connection, it silently stops forwarding in both
directions and keeps the sockets open (no RST), like the censor does.

usage: freezer.py LISTEN_PORT UPSTREAM_HOST:PORT LIMIT_BYTES
"""
import asyncio
import sys

listen_port = int(sys.argv[1])
up_host, up_port = sys.argv[2].rsplit(":", 1)
limit = int(sys.argv[3])
stats = {"conns": 0, "frozen": 0}


async def handle(cr, cw):
    stats["conns"] += 1
    n = stats["conns"]
    try:
        ur, uw = await asyncio.open_connection(up_host, int(up_port))
    except OSError:
        cw.close()
        return
    state = {"down": 0, "frozen": False}

    async def pipe(r, w, down):
        try:
            while True:
                data = await r.read(65536)
                if not data:
                    break
                if state["frozen"]:
                    continue  # swallow silently
                if down:
                    room = limit - state["down"]
                    if len(data) > room:
                        data = data[:max(room, 0)]
                        state["frozen"] = True
                        stats["frozen"] += 1
                        print(f"conn {n}: frozen after {limit} bytes", flush=True)
                    state["down"] += len(data)
                if data:
                    w.write(data)
                    await w.drain()
        except (ConnectionError, OSError):
            pass
        if not state["frozen"]:
            try:
                w.close()
            except Exception:
                pass

    await asyncio.gather(pipe(cr, uw, False), pipe(ur, cw, True))


async def main():
    srv = await asyncio.start_server(handle, "127.0.0.1", listen_port)
    print(f"freezer on :{listen_port} → {up_host}:{up_port}, limit {limit} B", flush=True)
    async with srv:
        await srv.serve_forever()

asyncio.run(main())
