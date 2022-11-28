# req2python
Convert a raw http request to a python3 object.



```bash
$ nc -lnp 8080 | tee example.req
GET /testing HTTP/1.1
Host: localhost:8080
User-Agent: curl/7.86.0
Accept: */*

$ cat ./example.req | ./req2python.py 
#!/usr/bin/env python3
import requests

s = requests.session()
try:
    from http.client import HTTPConnection
    HTTPConnection._http_vsn_str = "HTTP/1.1"
except KeyError:
    pass
headers = {
 "Host": "localhost:8080",
 "User-Agent": "curl/7.86.0",
 "Accept": "*/*",
}
data = b''
url = 'https://localhost:8080/testing'
r = s.get(
    url=url, 
    headers=headers,
    data=data,
)
print(r.text)

```


help:
```bash
$ ./req2python.py -h
usage: req2python.py [-h] [-outfile [OUTFILE]] [-request-proto [REQUEST_PROTO]] [-session-variable [SESSION_VARIABLE]] [-pretty-json] [-write-shebang] [-remove-content-length] [infile]

positional arguments:
  infile

options:
  -h, --help            show this help message and exit
  -outfile [OUTFILE]    Append the request session to file instead of stdout
  -request-proto [REQUEST_PROTO]
                        The request will be made with prototype (default: https)
  -session-variable [SESSION_VARIABLE]
                        Session variable (default: s)
  -pretty-json          Make the json pretty (default: True)
  -write-shebang        Initialise the file with shebang, importing requests and session variable (default: True)
  -remove-content-length
                        Remove content length (default: True)
```