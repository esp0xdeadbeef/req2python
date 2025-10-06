#!/usr/bin/env python3
"""
req2python_safe_template.py with SSL verify handling and timeout.

- Adds explicit --insecure / -k flag to disable TLS verification.
- httpx: verify=False is set in Client when --insecure or proxy used.
- curl_cffi: verify=False passed per request when --insecure or proxy used.
- Timeout of 120s added (httpx.Client(timeout=120.0), curl_cffi per-call timeout=120.0).
"""
from __future__ import annotations
import argparse
import sys
import json
from http.server import BaseHTTPRequestHandler
from io import BytesIO
from string import Template
from typing import Tuple, Dict


def read_stdin_or_file(infile_object) -> bytes:
    with infile_object as f:
        raw_in_file = f.read()
    if isinstance(raw_in_file, bytes):
        return raw_in_file
    return raw_in_file.encode()


class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text: bytes):
        self.rfile = BytesIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message


def parse_request(infile_object, request_proto: str = "https") -> Tuple[str, str, Dict[str, str], bytes, str, str, bool]:
    in_file = read_stdin_or_file(infile_object)
    in_file = in_file.replace(b"HTTP/2", b"HTTP/1.1")
    request = HTTPRequest(in_file)
    if request.error_code is not None:
        raise ValueError(f"Error parsing request: {request.error_message}")

    headers = dict(request.headers)
    headers.pop("Content-Length", None)
    headers.pop("content-length", None)

    try:
        url = f"{request_proto}://{headers['Host']}{request.path}"
    except KeyError:
        url = request.path

    potential_proto_headers = ["Referer", "Origin"]
    alert_request_proto = any(
        headers.get(h, "").split(":", 1)[0] != request_proto
        for h in potential_proto_headers if headers.get(h)
    )

    body = request.rfile.read()

    return (
        request.command,
        url,
        headers,
        body,
        request.path,
        request.request_version,
        alert_request_proto,
    )


def build_script(method: str, url: str, headers: Dict[str, str], data: bytes, path: str, http_vsn_str: str, alert_request_proto: bool, args: argparse.Namespace) -> str:
    if args.remove_content_length:
        headers.pop("Content-Length", None)
        headers.pop("content-length", None)

    if args.framework == "httpx":
        verify_flag = ", verify=False" if args.insecure or args.proxy_variable else ""
        proxy_flag = f", proxy=\"{args.proxy_variable}\"" if args.proxy_variable else ""
        shebang = f"""#!/usr/bin/env python3\nimport httpx\n{args.session_variable} = httpx.Client(http2=True{proxy_flag}{verify_flag}, timeout=120.0)\n"""
        framework_methods = {"get", "post", "put", "delete", "patch", "options", "head"}
        extra_call_args = ""  # httpx: handled at Client level
    elif args.framework == "curl":
        shebang = f"""#!/usr/bin/env python3\nimport curl_cffi.requests as requests\n{args.session_variable} = requests.Session(http_version=\"3\")\n"""
        framework_methods = {"get", "post", "put", "delete", "patch", "options", "head"}
        extra_call_args = "timeout=120.0,"
        if args.insecure or args.proxy_variable:
            extra_call_args = "verify=False, timeout=120.0,"
        if args.proxy_variable:
            extra_call_args += f" proxies={{'http': '{args.proxy_variable}', 'https': '{args.proxy_variable}'}},"
    else:
        raise ValueError("Unsupported framework; choose 'httpx' or 'curl'")

    url_from_argparse = f"url = '{url}'\n"
    if alert_request_proto:
        url_from_argparse += "print('Warning: request proto mismatch')\n"

    try:
        headers_pretty = json.dumps(headers, indent=4, sort_keys=False)
    except Exception:
        headers_pretty = repr(headers)

    is_json = False
    if data:
        try:
            decoded = data.decode('latin-1')
            parsed = json.loads(decoded)
            data_pretty = json.dumps(parsed, indent=4, sort_keys=False)
            is_json = True
        except Exception:
            try:
                text = data.decode('latin-1')
                data_pretty = "'''%s'''" % text.replace("'''", "\\'\\'\\'")
            except Exception:
                data_pretty = repr(data)
    else:
        data_pretty = "b''"

    method_lower = method.lower()
    call_method = method_lower if method_lower in framework_methods else "request"

    body_arg = "json=data" if is_json else ("content=data" if args.framework == "httpx" else "data=data")

    maybe_extra = ("\n        " + extra_call_args) if extra_call_args else ""

    template = Template(
        "$shebang\n"
        "$url_from_argparse\n"
        "try:\n"
        "    from http.client import HTTPConnection\n"
        "    HTTPConnection._http_vsn_str = \"$http_vsn_str\"\n"
        "except Exception:\n"
        "    pass\n\n"
        "headers = $headers\n"
        "data = $data\n\n"
        "try:\n"
        "    $response_var = $session_variable.$call_method(\n"
        "        url,\n"
        "        headers=headers,\n"
        "        $body_arg$maybe_extra\n"
        "    )\n"
        "except Exception as e:\n"
        "    print('Request failed:', e)\n"
        "    raise\n\n"
        "print($response_var.text)\n"
    )

    return template.substitute(
        shebang=shebang,
        url_from_argparse=url_from_argparse,
        http_vsn_str=http_vsn_str,
        headers=headers_pretty,
        data=data_pretty,
        response_var=args.response_var,
        session_variable=args.session_variable,
        call_method=call_method,
        body_arg=body_arg + ",",
        maybe_extra=maybe_extra,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('infile', nargs='?', type=argparse.FileType('rb'), default=sys.stdin)
    parser.add_argument('-outfile', nargs='?', type=argparse.FileType('w', encoding='latin-1'), default=sys.stdout)
    parser.add_argument('-framework', choices=['httpx', 'curl'], default='httpx')
    parser.add_argument('-request-proto', nargs='?', type=str, default='https')
    parser.add_argument('-session-variable', nargs='?', type=str, default='s')
    parser.add_argument('-proxy-variable', nargs='?', type=str, default='')
    parser.add_argument('-response-var', type=str, default='r')
    parser.add_argument('-pretty-json', action='store_true', default=True)
    parser.add_argument('-write-shebang', action='store_true', default=True)
    parser.add_argument('-remove-content-length', action='store_true', default=True)
    parser.add_argument('-make-url-argparse', action='store_true', default=False)
    parser.add_argument('-url-as-argument-without-path', action='store_true', default=True)
    parser.add_argument('-k', '--insecure', action='store_true', default=False,
                        help='Disable TLS verification (like curl -k)')

    args = parser.parse_args()

    method, url, headers, data, path, http_vsn_str, alert_request_proto = parse_request(args.infile, args.request_proto)

    script = build_script(method, url, headers, data, path, http_vsn_str, alert_request_proto, args)
    args.outfile.write(script)
    args.outfile.flush()


if __name__ == '__main__':
    main()
