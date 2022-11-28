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