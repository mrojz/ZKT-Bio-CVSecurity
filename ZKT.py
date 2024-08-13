import json, hashlib
from mitmproxy import http
from time import time

def request(flow: http.HTTPFlow) -> None:
    URL = flow.request.url
    if URL.split(":8098")[1]=="/app/v1/photoBase64":
        enc=hashlib.md5()
        request_body = flow.request.content
        json_request = json.loads(request_body)
        json_request['nonce']="12345678901234567890"
        json_request['timestamp']=str(int(time())*1000)
        enc.update(json_request['path'].encode()+json_request['nonce'][4:16].encode()+json_request['timestamp'].encode())
        enc1=enc.hexdigest()
        json_request['sign'] = enc1.upper()
        flow.request.text = json.dumps(json_request)

def response(flow: http.HTTPFlow) -> None:
    pass