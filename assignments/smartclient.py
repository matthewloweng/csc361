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
            # Create an SSL context object with SSLv23 method
            ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)

            # Set the ALPN protocols for negotiation
            ctx.set_alpn_protocols(['http/1.1', 'h2'])

            # Wrap the socket using the SSL context
            s = ctx.wrap_socket(s, server_hostname=parsed_uri['domain'])

        s.connect((parsed_uri['domain'], parsed_uri['port']))
        request = create_request(parsed_uri['domain'], parsed_uri['path'])
        
        # Print the HTTP request
        print_request(request)
        
        s.send(request.encode())
        response = s.recv(4096)
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data
        s.close()
        
        # Print the HTTP response
        print_response(response.decode(errors="replace"))
        
        return response.decode(errors="replace")
    except Exception as e:
        print("Error connecting to server:", e)
        sys.exit(1)

# Printing intermediate results
def print_request(request):
    print("\n---Request begin---")
    for line in request.split("\r\n"):
        if line.strip():  # Only print non-empty lines
            print(line)
    print("---Request end---")
    print("HTTP request sent, awaiting response...\n")

# Still printing intermediate results
def print_response(response):
    headers, body = response.split("\r\n\r\n", 1)
    print("\n---Response header ---")
    for line in headers.split("\r\n"):
        if line.strip():  # Only print non-empty lines
            print(line)
    print("\n--- Response body ---")


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

    # Handling redirects
    headers, _ = response.split("\r\n\r\n", 1)
    while "HTTP/1.1 301" in headers or "HTTP/1.1 302" in headers:
        for line in headers.split("\r\n"):
            if "Location:" in line:
                new_uri = line.split(": ", 1)[1]
        parsed_uri = parse_uri(new_uri)
        response = connect_and_fetch(parsed_uri)
        headers, _ = response.split("\r\n\r\n", 1)

    supports_http2, cookies, password_protected = process_response(response)

    # Display the results
    print(f'\nwebsite: {parsed_uri["domain"]}')
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
