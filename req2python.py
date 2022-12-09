#!/usr/bin/env python3
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
     

def parse_request(infile_object):
    in_file = read_stdin_or_file(infile_object)
    splitted_req = in_file.split(b'\r\n\r\n', 1)
    data = splitted_req[-1]

    headers_with_method_row = splitted_req[0]
    headers_raw = headers_with_method_row.split(b'\r\n')[1:]
    headers = {}
    for header in headers_raw:
        current_header = header.decode('latin-1').split(':', 1)
        headers[current_header[0].strip()] = current_header[1].strip()
    method, path, http_vsn_str = headers_with_method_row.split(b'\r\n')[0].decode().split(' ')
    
    try:
        url = args.request_proto + '://' + headers['Host'] + path
    except KeyError:
        url = path
    
    potential_proto_headers = ['Referer', 'Origin']
    alert_request_proto = False
    for potential_proto_header in potential_proto_headers:
        try:
            if headers[potential_proto_header].split(':',1)[0] != args.request_proto:
                alert_request_proto = True
                break
        except KeyError:
            pass
    
    return method, url, headers, data, path, http_vsn_str, alert_request_proto


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
    action='store_true', 
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
    ## cat example.req | python3 req2python.py -request-proto http -url-as-argument-without-path
    ## url variable:
    # url = 'http://localhost:8000/'
    ## inside request:
    # url=url + "/" + path/on/server
    url, path = ('/'.join(url.split('/')[:3]) + "/", '/'.join(url.split('/')[3:]))
    variables_request_args['url'] = f"url + \"/{path}\""
else:
    ## cat example.req | python3 req2python.py -request-proto http
    ## url variable:
    # url = 'http://localhost:8000/testing'
    ## inside request:
    # url=url
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


requests_methods = []
with open(sysconfig.get_paths()["purelib"] + "/requests/api.py", 'r') as f:
    for i in f.readlines():
        if 'def ' in i and not 'request(' in i:
            requests_methods.append(i.split('def ', 1)[-1].split('(',1)[0])

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
