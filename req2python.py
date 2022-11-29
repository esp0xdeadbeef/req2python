#!/usr/bin/env python3
import argparse
# import requests
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
    method_row = headers_with_method_row.split(b'\r\n')[0].decode().split(' ')
    try:
        url = args.request_proto + '://' + headers['Host'] + method_row[1]
    except KeyError:
        url = method_row[1]
    
    potential_proto_headers = ['Referer', 'Origin']
    for potential_proto_header in potential_proto_headers:
        try:
            if headers[potential_proto_header].split(':',1)[0] != args.request_proto:
                print('I think you have the wrong request-proto filled in, but hey let\'s go.')
        except KeyError:
            pass
    method = method_row[0]
    
    return method, url, headers, data, method_row


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
# parser.add_argument(
#     '-make-url-stdin', 
#     action='store_false', 
#     default=True,
#     help='Remove content length (default: %(default)s)'
# )

args = parser.parse_args()
method, url, headers, data, method_row = parse_request(args.infile)

session_variable = args.session_variable# "s"
response_var = "r"
tabs = "    "

for i in ['Content-Length', 'content-length']:
    try:
        if args.remove_content_length:
            headers.pop(i)
    except KeyError:
        pass


headers_pretty = headers
data_pretty = data
json_data_type = False

if args.pretty_json:
    try:
        headers_pretty = json.dumps(headers, indent=1, sort_keys=False).replace('\n}', ',\n}')
    except:
        headers_pretty = headers
    try:
        data_pretty = json.dumps(json.loads(data.decode('latin-1')), indent=1, sort_keys=False).replace('\n}', ',\n}')
        json_data_type = True
    except json.decoder.JSONDecodeError:
        data_pretty = data
        json_data_type = False

ret_val = ""
if args.write_shebang:
    ret_val += f"#!/usr/bin/env python3\n"
    ret_val += f"import requests\n\n"
    ret_val += f"{session_variable} = requests.session()\n"
    
ret_val += f"""try:
    from http.client import HTTPConnection
    HTTPConnection._http_vsn_str = "{method_row[-1]}"
except KeyError:
    pass
"""


ret_val += f"headers = {headers_pretty!s}\n"
ret_val += f"data = {data_pretty!s}\n"
ret_val += f"url = '{url}'\n"

requests_methods = []
with open(sysconfig.get_paths()["purelib"] + "/requests/api.py", 'r') as f:
    for i in f.readlines():
        if 'def ' in i and not 'request(' in i:
            requests_methods.append(i.split('def ', 1)[-1].split('(',1)[0])

if method.lower() in requests_methods:
    ret_val += f'{response_var} = {session_variable}.{method.lower()}(\n'
else:
    ret_val += f'{response_var} = {session_variable}.request(\n'
    ret_val += f'{tabs * 1!s}method="{method}",\n'
    
ret_val += f"{tabs * 1!s}url=url, \n"
ret_val += f"{tabs * 1!s}headers=headers,\n"

if json_data_type:       
    ret_val += f"{tabs * 1!s}json=data,\n"
else:
    ret_val += f"{tabs * 1!s}data=data,\n"

ret_val += f"{tabs * 1!s}" + "# proxies={\n"
ret_val += f"{tabs * 1!s}" + "#" + f"{tabs * 1!s}" + " 'http': 'http://127.0.0.1:8080'\n"
ret_val += f"{tabs * 1!s}" + "# },\n"
ret_val += f"{tabs * 1!s}# allow_redirects = False,\n"
ret_val += f")"
# if args.make_url_stdin:
#     ret_val = ret_val.replace(url, 'url')

ret_val = ret_val.encode('latin-1')

ret_val += b"\nprint(r.text)\n"



args.outfile.write(ret_val.decode('latin-1'))
