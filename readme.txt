Overview:
---------
The smartclient.py script is a tool designed to fetch web pages over HTTP/HTTPS. It provides insights into the websites it fetches, such as support for HTTP/2, the list of cookies set by the server, and whether the website is password protected.

Features:
---------
1. Fetch web pages over HTTP/HTTPS.
2. Display the full HTTP request and response.
3. Handle HTTP redirects (301 & 302).
4. Detect HTTP/2 support.
5. List all cookies set by the server.
6. Detect if the website is password-protected.

Requirements:
-------------
1. Python 3.x
2. The `socket` and `ssl` modules from Python's standard library.

Usage:
------
To use the script, execute it from the command line with a URI as an argument. For example:

python3 smartclient.py https://uvic.ca

OR

python3 smartclient.py uvic.ca

Functions:
----------
- `parse_uri(uri)`: Parses the provided URI into its constituent components.
- `connect_and_fetch(parsed_uri)`: Connects to the provided domain and port, and fetches the web page at the specified path.
- `print_request(request)`: Prints the HTTP request.
- `print_response(response)`: Prints the HTTP response.
- `create_request(domain, path)`: Creates an HTTP GET request for the provided domain and path.
- `process_response(response)`: Processes the HTTP response to determine HTTP/2 support, cookies, and if the site is password protected.
- `smart_client(uri)`: The main function. Uses the other functions to fetch and process a web page.

Notes:
------
- The script handles HTTP redirects (HTTP 301 and 302 status codes) by following the "Location" header in the response until a non-redirect response is received.
