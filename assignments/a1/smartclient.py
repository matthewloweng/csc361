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


def connect_and_fetch(parsed_uri):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if parsed_uri['protocol'] == 'https':
            s = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_SSLv23)
        s.connect((parsed_uri['domain'], parsed_uri['port']))
        request = create_request(parsed_uri['domain'], parsed_uri['path'])
        print_request(request)
        s.send(request)
        response = s.recv(4096)
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data
        s.close()
        print_response(response)
        return response
    except Exception as e:
        print("Error connecting to server: {}".format(e))
        sys.exit(1)

def print_request(request):
    print("\n---Request begin---")
    for line in request.split("\r\n"):
        if line.strip():
            print(line)
    print("---Request end---")
    print("HTTP request sent, awaiting response...\n")

def print_response(response):
    headers, body = response.split("\r\n\r\n", 1)
    print("\n---Response header ---")
    for line in headers.split("\r\n"):
        if line.strip():
            print(line)
    print("\n--- Response body ---")

def create_request(domain, path):
    request = "GET {} HTTP/1.1\r\n".format(path)
    request += "Host: {}\r\n".format(domain)
    request += "Connection: close\r\n"
    request += "\r\n"
    return request

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
    headers, _ = response.split("\r\n\r\n", 1)
    while "HTTP/1.1 301" in headers or "HTTP/1.1 302" in headers:
        for line in headers.split("\r\n"):
            if "Location:" in line:
                new_uri = line.split(": ", 1)[1]
        parsed_uri = parse_uri(new_uri)
        response = connect_and_fetch(parsed_uri)
        headers, _ = response.split("\r\n\r\n", 1)
    supports_http2, cookies, password_protected = process_response(response)
    print('\nwebsite: {}'.format(parsed_uri["domain"]))
    print('1. Supports http2: {}'.format("yes" if supports_http2 else "no"))
    print('2. List of Cookies: ')
    for cookie_name, domain_name in cookies:
        print('cookie name: {}, domain name: {}'.format(cookie_name, domain_name))
    print('3. Password-protected: {}'.format("yes" if password_protected else "no"))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script_name.py <URI>")
        sys.exit(1)
    uri = sys.argv[1]
    smart_client(uri)
