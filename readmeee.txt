--------------------------
SMART CLIENT TOOL README
--------------------------

OVERVIEW:
----------
This smartclient is a tool for collecting specific information about a web server. 

FEATURES:
----------
1. Parsing URI to extract protocol, domain, port, and file path.
2. Using sockets to communicate with the specified server.
3. Creating and sending HTTP requests.
4. Processing the server's response to determine:
   - HTTP/2 support
   - Set cookies by the server
   - Whether the site is password-protected or not

HOW TO USE:
-----------
1. Ensure you have Python installed on your system.
2. Open a terminal or command prompt.
3. Navigate to the directory containing the script.
4. Run the script by using the command:

Replace `<URI>` with the web address you want to check.
Example: `python smartclient.py https://www.example.com`

OUTPUT:
-------
After execution, the smart client displays the following:
1. If the server supports HTTP/2.
2. A list of cookies set by the server, including their names and domain attributes.
3. Whether the site is password-protected.

ERRORS:
-------
In case of an error in connection or other issues, the smart client will provide an appropriate error message and exit.

NOTES:
------
1. This tool supports both HTTP and HTTPS protocols.
2. Make sure to provide the complete URI for accurate results.