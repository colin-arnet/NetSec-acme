from dnslib import RR, QTYPE, A, DNSLabel
from dnslib.server import BaseResolver, DNSServer
from threading import Thread

class DNSResolver(BaseResolver):
    def __init__(self, ip_adress):
        super().__init__()
        self.ip = ip_adress
        self.records = []

    def resolve(self, request, handler):
        reply = request.reply()
        qname = request.q.qname
        qtype = request.q.qtype
        answer_bool = False
        for record in self.records:
            if record[0].get_rname() == qname and record[0].rtype == qtype:
                reply.add_answer(record[0])
                answer_bool = True
        if not answer_bool and qtype == QTYPE.A:
            reply.add_answer(RR(rname=qname, rtype=qtype, ttl=300, rdata=A(self.ip)))
        return reply
    
    def add_record(self, zone):
        self.records.append(RR.fromZone(zone))

def start_dns_server(ip_adress):
    print("Start DNS Server")
    resolver = DNSResolver(ip_adress)
    server = DNSServer(resolver, ip_adress, port=10053)
    server.resolver = resolver
    t = Thread(target=server.start)
    t.start()
    return server

def stop_dns_server(server):
    print("Stop DNS Server")
    server.stop()