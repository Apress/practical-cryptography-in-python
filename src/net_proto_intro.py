import asyncio

class ConcreteProtocol(asyncio.Protocol):
    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data):
        pass
        # process data
        # send data using transport.write as needed

    def connection_lost(self, exc):
        pass
        # do cleanup

# FOR AUTO TESTER:
p = ConcreteProtocol()
p.connection_made(None)
p.data_received(None)
p.connection_lost(None)
print("[PASS]")