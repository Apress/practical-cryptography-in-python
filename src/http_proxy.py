import asyncio

class ProxySocket(asyncio.Protocol):
    CONNECTED_RESPONSE = (
        b"HTTP/1.0 200 Connection established\n"
        b"Proxy-agent: East Antarctica Spying Agency\n\n")

    def __init__(self, proxy):
        self.proxy = proxy

    def connection_made(self, transport):
        self.transport = transport
        self.proxy.proxy_socket = self
        self.proxy.transport.write(self.CONNECTED_RESPONSE)

    def data_received(self, data):
        print("PROXY RECV:", data)
        self.proxy.transport.write(data)

    def connection_lost(self, exc):
        self.proxy.transport.close()


class HTTPProxy(asyncio.Protocol):
    def connection_made(self, transport):
        peername = transport.get_extra_info('peername')
        print('Connection from {}'.format(peername))
        self.transport = transport
        self.proxy_socket = None

    def data_received(self, data):
        if self.proxy_socket:
            print("PROXY SEND:", data)
            self.proxy_socket.transport.write(data)
            return

        # No socket, we need to see CONNECT.
        if not data.startswith(b"CONNECT"):
            print("Unknown method")
            self.transport.close()
            return

        print("Got CONNECT command:", data)
        serverport = data.split(b" ")[1]
        server, port = serverport.split(b":")
        coro = loop.create_connection(lambda: ProxySocket(self), server, port)
        asyncio.get_event_loop().create_task(coro)

    def connection_lost(self, exc):
        if not self.proxy_socket: return
        self.proxy_socket.transport.close()
        self.proxy_socket = None

loop = asyncio.get_event_loop()
coro = loop.create_server(HTTPProxy, '127.0.0.1', 8888)
server = loop.run_until_complete(coro)

# Serve requests until Ctrl+C is pressed
print('Proxying on {}'.format(server.sockets[0].getsockname()))
try:
    loop.run_forever()
except KeyboardInterrupt:
    pass

# Close the server
server.close()
loop.run_until_complete(server.wait_closed())
loop.close()
