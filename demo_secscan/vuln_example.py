import subprocess, pickle, hashlib, yaml, requests, urllib3

password = "SuperSecret123"  # hardcoded password
AWS_KEY = "AKIAABCDEFGHIJKLMNOP"  # looks like an AWS Access Key ID

def run_cmd(cmd):
    # Небезопасно: shell=True
    subprocess.run(cmd, shell=True)

def unsafe_pickle(data):
    return pickle.loads(data)

def weak_hash(data):
    return hashlib.md5(data).hexdigest()

def yaml_bad_load(s):
    return yaml.load(s)  # без SafeLoader

def insecure_request(url):
    urllib3.disable_warnings()
    return requests.get(url, verify=False)
