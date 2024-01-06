import cryptography
import click
import os
import shutil
import time


from client import Client
import DNS_Server
import HTTP_Server

# TODO:
# - finish implementation (finalize order, get certificate, set everything up)
# - integrate challenge types (see project description)
# - test if it works. challenges are probably wrong
# - clean up for submission



@click.command()
@click.argument('challenge_type')
@click.option('--dir', required=True)
@click.option('--record', required=True)
@click.option('--domain', required=True, multiple=True)
@click.option('--revoke', is_flag=True)
def main(challenge_type, dir, record, domain, revoke):
    if ((not challenge_type == 'dns01') and (not challenge_type == 'http01')):
        return
    timeout = 60
    retry_interval = 1
    client = Client(dir, challenge_type, timeout, retry_interval)
    dns_server = DNS_Server.start_dns_server(record)
    client.dns_server = dns_server
    challenge_server = HTTP_Server.start_challenge_server()
    shutdown_server = HTTP_Server.start_shutdown_server()
    if not os.path.exists('home/.well-known/acme-challenger'):
        os.makedirs('home/.well-known/acme-challenge', exist_ok=True) 
    client.create_account()
    client.put_order(list(domain))
    client.get_challenges()
    client.prove_control()
    # client.check_authorizations()
    client.check_order()
    client.finalize_order()
    client.download_cert()
    cert_server = HTTP_Server.start_certificate_server()
    if revoke:
        client.revoke_certificate()
    while shutdown_server.keep_running == True:
        time.sleep(retry_interval)  
    DNS_Server.stop_dns_server(dns_server)
    HTTP_Server.stop_http_server(challenge_server)
    HTTP_Server.stop_http_server(cert_server)
    HTTP_Server.stop_http_server(shutdown_server)
    shutil.rmtree('home/')
    
    
    

if __name__ == '__main__':
    main()