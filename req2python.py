#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler
from io import BytesIO
import argparse
from string import Template
import sys
import json
import sysconfig

def read_stdin_or_file(infile_object):
    with infile_object as f:
        raw_in_file = f.read()
    if 'bytes' in str(type(raw_in_file)):
        return raw_in_file
    return raw_in_file.encode()


class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = BytesIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()  # This method automatically parses the request

    def send_error(self, code, message):
        """Override to prevent sending errors to a client."""
        self.error_code = code
        self.error_message = message

def parse_request(infile_object):
    """
    Parse an HTTP request, extracting method, URL, headers, and data.
    Allows HTTP/2 by converting it to HTTP/1.1.
    """
    # Read input from stdin or file
    in_file = read_stdin_or_file(infile_object)

    # Preprocess: Replace HTTP/2 with HTTP/1.1 (since BaseHTTPRequestHandler only supports HTTP/1.x)
    in_file = in_file.replace(b"HTTP/2", b"HTTP/1.1")

    # Parse using the HTTPRequest class
    request = HTTPRequest(in_file)

    # Handle parsing errors
    if request.error_code is not None:
        raise ValueError(f"Error in parsing request: {request.error_message}")

    # Convert headers to a dictionary for easier modification
    headers = dict(request.headers)

    for header in ['Content-Length', 'content-length']:
        headers.pop(header, None) 

    # Build the URL from the headers and path
    try:
        url = f"{args.request_proto}://{headers['Host']}{request.path}"
    except KeyError:
        url = request.path

    # Alert if any headers suggest a different protocol
    potential_proto_headers = ['Referer', 'Origin']
    alert_request_proto = any(
        headers.get(header, '').split(':', 1)[0] != args.request_proto
        for header in potential_proto_headers
    )

    return (
        request.command,             # HTTP method (GET, POST, etc.)
        url,                         # Full URL
        headers,                     # Parsed headers (now a dict)
        request.rfile.read(),        # Request body
        request.path,                # The requested path
        request.request_version,     # HTTP version (e.g., HTTP/1.1)
        alert_request_proto          # Alert for protocol mismatches
    )


parser = argparse.ArgumentParser()
parser.add_argument(
    'infile',
    nargs='?',
    type=argparse.FileType('rb'),
    default=sys.stdin
)
parser.add_argument(
    '-outfile',
    nargs='?',
    type=argparse.FileType(
        'a',
        encoding='latin-1'
        ),
    default=sys.stdout,
    help="Append the request session to file instead of stdout",
)
parser.add_argument(
    '-request-proto',
    nargs='?',
    type=str,
    default="https",
    help='The request will be made with prototype (default: %(default)s)'
)
parser.add_argument(
    '-session-variable',
    nargs='?',
    type=str,
    default="s",
    help='Session variable (default: %(default)s)'
)
parser.add_argument(
    '-proxy-variable',
    type=str,
    default="http://127.0.0.1:8080",
    help='Proxy variable in output (default: %(default)s)'
)
parser.add_argument(
    '-response-var',
    type=str,
    default="r",
    help='Request result variable (default: %(default)s)'
)
parser.add_argument(
    '-pretty-json',
    action='store_false',
    default=True,
    help='Make the json pretty (default: %(default)s)'
)
parser.add_argument(
    '-write-shebang',
    action='store_false',
    default=True,
    help='Initialise the file with shebang, importing requests and session variable (default: %(default)s)'
)
parser.add_argument(
    '-remove-content-length',
    action='store_false',
    default=True,
    help='Remove content length (default: %(default)s)'
)
parser.add_argument(
    '-make-url-argparse',
    action='store_true',
    default=False,
    help='Remove content length (default: %(default)s)'
)

parser.add_argument(
    '-url-as-argument-without-path',
    action='store_false',
    default=True,
    help='Remove content length (default: %(default)s)'
)

args = parser.parse_args()
method, url, headers, data, path, http_vsn_str, alert_request_proto = parse_request(args.infile)



tabs = "    "

for i in ['Content-Length', 'content-length']:
    try:
        if args.remove_content_length:
            headers.pop(i)
    except KeyError:
        pass


requests_args = Template("""url=$url,
    headers=headers,
    data=data,
    # proxies={
    #    'http': '$proxy_variable'
    # },
    # allow_redirects=False,""")

variables_request_args = {
    "proxy_variable": args.proxy_variable
}

if args.url_as_argument_without_path:
    url, path = ('/'.join(url.split('/')[:3]), '/'.join(url.split('/')[3:]))
    variables_request_args['url'] = f"url + \"/{path}\""
else:
    variables_request_args['url'] = "url"

requests_args = str(requests_args.substitute(variables_request_args))

if args.pretty_json:
    try:
        headers_pretty = json.dumps(headers, indent=4, sort_keys=False).replace('\n}', ',\n}')
    except:
        headers_pretty = headers
    try:
        data_pretty = json.dumps(json.loads(data.decode('latin-1')), indent=4, sort_keys=False).replace('\n}', ',\n}')
        json_data_type = True
        requests_args = requests_args.replace('data=data', 'json=data')
    except json.decoder.JSONDecodeError:
        data_pretty = data
        json_data_type = False


#requests_methods = []
#with open(sysconfig.get_paths()["purelib"] + "/requests/api.py", 'r') as f:
#    for i in f.readlines():
#        if 'def ' in i and not 'request(' in i:
#            requests_methods.append(i.split('def ', 1)[-1].split('(',1)[0])
#import requests.api as _api

#requests_methods = [name for name in _api.__all__ if name != "request"]
import inspect
import requests.api as _api     # sub-module that defines the helpers

requests_methods = [
    name
    for name, obj in inspect.getmembers(_api, inspect.isfunction)
    if obj.__module__ == _api.__name__ and name != "request"
]

print(requests_methods)
# → ['get', 'post', 'put', 'patch', 'delete', 'head', 'options']



if method.lower() in requests_methods:
    requests_method = method.lower()
else:
    requests_method = f'request'
    requests_args = f'method="{method}",\n    ' + requests_args


shebang = ""
if args.write_shebang:
    shebang += f"""#!/usr/bin/env python3
import requests
{args.session_variable} = requests.session()
"""


if args.make_url_argparse:
    url_from_argparse = f"""import argparse
parser = argparse.ArgumentParser()
parser.add_argument(
    '-url',
    type=str,
    default="{url}",
    help='Request result variable (default: %(default)s)'
)
args = parser.parse_args()
url = args.url
"""
else:
    url_from_argparse = f"url = '{url}'\n"
    if alert_request_proto:
        url_from_argparse += "print('The url is probably a different prototype then the official service.')\n"

template_for_request_python3 = Template("""$shebang
$url_from_argparse
try:
    from http.client import HTTPConnection
    HTTPConnection._http_vsn_str = "$http_vsn_str"
except KeyError:
    pass

headers = $headers
data = $data

$response_var = $session_variable.$requests_method(
    $request_args
)
print($response_var.text)
""")


url = f"'{url}'"

variables = {
    'shebang': shebang,
    'url_from_argparse': url_from_argparse,
    'http_vsn_str': http_vsn_str,
    'headers': headers_pretty,
    'data': data_pretty,
    'url': url,
    'session_variable': args.session_variable,
    'requests_method': requests_method,
    'response_var': args.response_var,
    'request_args': requests_args,
}

args.outfile.write(template_for_request_python3.substitute(variables).encode('latin-1').decode('latin-1'))
