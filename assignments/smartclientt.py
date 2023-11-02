# --- Tutorial 1: P1 Spec Go-through, Design Hints, Python ---

# P1 Goal: Build a tool at web client to collect information regarding a web server.
# Purpose:
# • Experience with socket programming in Python
# • Help students understand the application-layer protocols HTTP/HTTPs

# Background – URI (Uniform Resource Identifiers)
# Known as the combination of Uniform Resource Locators (URL)
# and Uniform Resource Names (URN)
# A formatted string which identifies a network resource, i.e.,
# protocol://host[:port]/filepath
# When a port is not specified, the default HTTP port number
# is 80, and the default HTTPS port number is 443.

import socket
import sys
import ssl

def parse_uri(uri):
    # Initialize default values
    protocol, domain, path, port = '', '', '/', 80

    # Check for protocol
    if '://' in uri:
        protocol, uri = uri.split('://', 1)
        if protocol == 'https':
            port = 443

    # Separate domain (or domain:port) from path
    if '/' in uri:
        domain_port, path = uri.split('/', 1)
        path = '/' + path
    else:
        domain_port = uri

    # Check for port in domain_port
    if ':' in domain_port:
        domain, port_str = domain_port.split(':', 1)
        port = int(port_str)
    else:
        domain = domain_port

    return {'protocol': protocol, 'domain': domain, 'port': port, 'path': path}


# --- Tutorial 2: Python Socket Programming and SSL ---

# Network Addressing
# Machines have a hostname and IP address
# Programs/services have port numbers
# Each endpoint of a network connection is always represented by a host and port #
# In Python you write it out as a tuple (host,port)
# ("www.python.org",80) ("205.172.13.4",443)
# In almost all of the network programs you’ll write, you use this convention to specify a network address
def connect_and_fetch(parsed_uri):
    try:
        # Sockets: Programming abstraction for network code
        # Socket: A communication endpoint
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        if parsed_uri['protocol'] == 'https':
            # Create an SSL context object with SSLv23 method
            ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)

            # Set the ALPN protocols for negotiation
            ctx.set_alpn_protocols(['http/1.1', 'h2'])

            # Wrap the socket using the SSL context
            s = ctx.wrap_socket(s, server_hostname=parsed_uri['domain'])

        s.connect((parsed_uri['domain'], parsed_uri['port']))
        request = create_request(parsed_uri['domain'], parsed_uri['path'])
        s.send(request.encode())
        response = s.recv(4096)
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data
        s.close()
        return response.decode(errors="replace")
    except Exception as e:
        print("Error connecting to server:", e)
        sys.exit(1)


# Background - HTTP
# HTTP request: a header and a body
def create_request(domain, path):
    request = f"GET {path} HTTP/1.1\r\n"
    request += f"Host: {domain}\r\n"
    request += "Connection: close\r\n"
    request += "\r\n"
    return request


# Process the response to determine HTTP/2 support, cookies, and if the site is password protected.
def process_response(response):
    headers, body = response.split("\r\n\r\n", 1)

    supports_http2 = "HTTP/2" in headers
    cookies = []
    password_protected = "401 Unauthorized" in headers

    for line in headers.split("\r\n"):
        if "Set-Cookie:" in line:
            parts = line.split(": ", 1)[1].split(";")
            cookie_name = parts[0].split("=", 1)[0]
            domain_name = None
            for part in parts[1:]:
                if "domain=" in part:
                    domain_name = part.split("=")[1]
            cookies.append((cookie_name, domain_name))

    return supports_http2, cookies, password_protected


def smart_client(uri):
    parsed_uri = parse_uri(uri)
    response = connect_and_fetch(parsed_uri)
    supports_http2, cookies, password_protected = process_response(response)

    # Display the results
    print(f'website: {parsed_uri["domain"]}')
    print(f'1. Supports http2: {"yes" if supports_http2 else "no"}')
    print(f'2. List of Cookies: ')
    for cookie_name, domain_name in cookies:
        print(f'cookie name: {cookie_name}, domain name: {domain_name}')
    print(f'3. Password-protected: {"yes" if password_protected else "no"}')


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script_name.py <URI>")
        sys.exit(1)
    uri = sys.argv[1]
    smart_client(uri)
