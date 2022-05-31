

# description:  http header vulnerability analysis project

import urllib3
from urllib3 import ProxyManager, make_headers, Retry, Timeout
import csv
import ssl
import json
import time
import requests
from tqdm import tqdm
from datetime import date


  
start_time = time.time()

today = date.today()

today = today.strftime("%Y-%m-%d")

#TODO 
#Argument à ajouter : 
#### Utilisation fichier
### Utilisation d'un proxy 
### Format de sortie 
### Mode analyse 
### mode conformité ( if existe | if contain | if match )

def get_lookup(target):

    query = f'{{"{target}":"1"}}'
    payload = {"query": query, "fields": "fqdn,code_app"}
    # print(f' {query} ==> {urllib.parse.quote(query)}')
    # response= requests.get('https://path/servicesNS/nobody/ICDC_DG_SG_MSEC/storage/collections/data/lookup_ref_url?query='+query, verify=False, auth=(SPLUNK_API_USER, SPLUNK_API_PASSWD))
    r = requests.get(
        "https://path/servicesNS/nobody/ICDC_DG_SG_MSEC/storage/collections/data/lookup_ref_url",
        params=payload,
        verify=False,
        auth=(SPLUNK_API_USER, SPLUNK_API_PASSWD),
    )

    info = f"GET {target}   :   {r.status_code}"
    print(info)
    res = r.json()
    return res


# print(get_lookup('scan_ssllab'))


# https://urllib3.readthedocs.io/en/stable/reference/urllib3.util.html


# status (int) –
# How many times to retry on bad status codes.
# These are retries made on responses, where status code matches status_forcelist.
# Set to 0 to fail on the first retry of this type.


# total (int) –
# Total number of retries to allow. Takes precedence over other counts.
# Set to None to remove this constraint and fall back on other counts.
# Set to 0 to fail on the first retry.
# Set to False to disable and imply raise_on_redirect=False.


retries = Retry(total=0, status=0)

start_time = time.time()

context = ssl._create_unverified_context()

http = ProxyManager(proxy, cert_reqs="CERT_NONE", retries=retries)

http = ProxyManager(proxy, cert_reqs="CERT_NONE")

ssl._create_default_https_context = ssl._create_unverified_context

# f = open("url.txt", "r")

# list_url = re.findall(r"((?:http[s]?://)?(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+)",f.read())

res = []


l = get_lookup("scan_securityheader")


# print('=====================================')

for item in tqdm(l):

    # print('=====================================')

    url = item["fqdn"]

    try:

        if "http" not in url:

            url = f"http://{url}"

        response = http.request("GET", url, timeout=Timeout(10, 10))

        # print(f'{url} : {response.status}')

        if response.status in [401, 200]:

            # print('HTTP Header Analysis for ' + url + ':' + '\n\n')

            # print(response)

            app = {
                "url": url,
                "date_scan": today,
                "status": response.status,
                "x-frame-options": bool(
                    "sameorigin" in response.getheader("x-frame-options").lower()
                )
                if response.getheader("x-frame-options") != None
                else False,
                "value x-frame-options": response.getheader("x-frame-options"),
                "strict-transport-security": bool(
                    "max-age" in response.getheader("strict-transport-security").lower()
                    and "includesubdomains"
                    in response.getheader("strict-transport-security").lower()
                )
                if response.getheader("strict-transport-security") != None
                else False,
                "value strict-transport-security": response.getheader(
                    "strict-transport-security"
                ),
                "content-security-policy": bool(
                    response.getheader("content-security-policy")
                )
                if response.getheader("content-security-policy") != None
                else False,
                
                "value content-security-policy": response.getheader(
                    "content-security-policy"
                ),
                "cache-control": bool(
                    "no-store" in response.getheader("cache-control").lower()
                    and "max-age=0" in response.getheader("cache-control").lower()
                )
                if response.getheader("cache-control") != None
                else False,
                "value cache-control": response.getheader("cache-control"),
                "x-permitted-cross-domain-policies": bool(
                    response.getheader("x-permitted-cross-domain-policies").lower()
                    == "none"
                )
                if response.getheader("x-permitted-cross-domain-policies") != None
                else False,
                "value x-permitted-cross-domain-policies": response.getheader(
                    "x-permitted-cross-domain-policies"
                ),
                "referrer-policy": bool(
                    response.getheader("referrer-policy").lower()
                    in ["same-origin", "sameorigin"]
                )
                if response.getheader("referrer-policy") != None
                else False,
                "value referrer-policy": response.getheader("referrer-policy"),
                "public-key-pins": bool(response.getheader("public-key-pins"))
                if response.getheader("public-key-pins") != None
                else False,
                "value public-key-pins": response.getheader("public-key-pins"),
                "x-content-type-options": bool(
                    response.getheader("x-content-type-options")
                )
                if response.getheader("x-content-type-options") != None
                else False,
                "value x-content-type-options": response.getheader(
                    "x-content-type-options"
                ),
                "headers": json.dumps(dict(response.getheaders())),
            }

            res.append(app)

        else:

            app = {
                "url": url,
                "date_scan": today,
                "status": response.status,
                "x-frame-options": "",
                "value x-frame-options": "",
                "strict-transport-security": "",
                "value strict-transport-security": "",
                "content-security-policy": "",
                "value content-security-policy": "",
                "cache-control": "",
                "value cache-control": "",
                "x-permitted-cross-domain-policies": "",
                "value x-permitted-cross-domain-policies": "",
                "referrer-policy": "",
                "value referrer-policy": "",
                "public-key-pins": "",
                "value public-key-pins": "",
                "x-content-type-options": "",
                "value x-content-type-options": "",
                "headers": json.dumps(dict(response.getheaders())),
            }

            res.append(app)

    except urllib3.exceptions.HTTPError as e:

        app = {
            "url": url,
            "date_scan": today,
            "status": e.reason,
            "x-frame-options": "",
            "value x-frame-options": "",
            "strict-transport-security": "",
            "value strict-transport-security": "",
            "content-security-policy": "",
            "value content-security-policy": "",
            "cache-control": "",
            "value cache-control": "",
            "x-permitted-cross-domain-policies": "",
            "value x-permitted-cross-domain-policies": "",
            "referrer-policy": "",
            "value referrer-policy": "",
            "public-key-pins": "",
            "value public-key-pins": "",
            "x-content-type-options": "",
            "value x-content-type-options": "",
            "headers": "",
        }

        res.append(app)

        # print('Request failed:', e.reason)

    # print(f'--- {(time.time() - start_time)} seconds --- ', end='', flush=True )


# print(len(res))


with open("-analyse.csv", "w", encoding="UTF8", newline="") as f:

    fieldnames = [
        "url",
        "status",
        "x-frame-options",
        "value x-frame-options",
        "strict-transport-security",
        "value strict-transport-security",
        "content-security-policy",
        "value content-security-policy",
        "cache-control",
        "value cache-control",
        "x-permitted-cross-domain-policies",
        "value x-permitted-cross-domain-policies",
        "referrer-policy",
        "value referrer-policy",
        "public-key-pins",
        "value public-key-pins",
        "x-content-type-options",
        "value x-content-type-options",
        "headers",
        "date_scan",
    ]

    writer = csv.DictWriter(
        f, fieldnames=fieldnames, delimiter=";", quoting=csv.QUOTE_ALL
    )

    writer.writeheader()

    writer.writerows(res)


print("Execution Time TOTAL ")

print("--- %s seconds ---" % (time.time() - start_time))

# #https://en.rakko.tools/tools/26/


# # #What this tool can

# # Check whether the website is a recommended HTTP response header that includes the following items effective for security measures:

# # HTTP Strict Transport Security (HSTS)

# # HTTP Public Key Pinning (HPKP) à ajouter =

# # X-Frame-Options

# # X-XSS-Protection

# # x-content-type-options

# # Content-Security-Policy

# # x-permitted-cross-domain-policies

# # referrer-policy

# # Expect-CT

# # Feature-Policy
