# req2python


Convert a raw HTTP request to a python3 object.

The test file for the example is this:

```bash
cat example.req; 
```

```
GET /testing HTTP/1.1
Host: localhost:8000
User-Agent: curl/7.86.0
Accept: */*
```

Let's convert it with default settings:

```bash
cat ./example.req | ./req2python.py 
# or
./req2python.py example.req
```

Output:

```bash
I think you have the wrong request-proto filled in, but hey let's go.
#!/usr/bin/env python3
import requests

s = requests.session()
try:
    from http.client import HTTPConnection
    HTTPConnection._http_vsn_str = "HTTP/1.1"
except KeyError:
    pass
headers = {
 "Host": "localhost:8000",
 "Referer": "http://localhost",
 "User-Agent": "curl/7.86.0",
 "Accept": "*/*",
}
data = b''
url = 'https://localhost:8000/testing'
r = s.get(
    url=url, 
    headers=headers,
    data=data,
    # proxies={
    #     'http': 'http://127.0.0.1:8080'
    # },
    # allow_redirects = False,
)
print(r.text)
```

Try HTTP instead:

```bash
cat ./example.req | ./req2python.py -request-proto http
# or
./req2python.py -request-proto http example.req
```

Output:

```bash
#!/usr/bin/env python3
import requests

s = requests.session()
try:
    from http.client import HTTPConnection
    HTTPConnection._http_vsn_str = "HTTP/1.1"
except KeyError:
    pass
headers = {
 "Host": "localhost:8000",
 "Referer": "http://localhost",
 "User-Agent": "curl/7.86.0",
 "Accept": "*/*",
}
data = b''
url = 'http://localhost:8000/testing'
r = s.get(
    url=url, 
    headers=headers,
    data=data,
    # proxies={
    #     'http': 'http://127.0.0.1:8080'
    # },
    # allow_redirects = False,
)
print(r.text)
```

Help:

```bash
./req2python.py -h
```

Output:

```
usage: req2python.py [-h] [-outfile [OUTFILE]] [-request-proto [REQUEST_PROTO]] [-session-variable [SESSION_VARIABLE]]
                     [-pretty-json] [-write-shebang] [-remove-content-length]
                     [infile]

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

# Problems:
Check if your request is formatted correctly, vim will edit the file with an \n\r at the end. The request will be failing if you try to send that request.
Solution:
```bash
cat ~/.vimrc
```
Output:
```
set nofixendofline
set noendofline
```