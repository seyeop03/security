
import requests
from requests.auth import HTTPDigestAuth
from urllib.parse import urlparse, urljoin


DEFAULT_VERIFY = False
DEFAULT_TIMEOUT = 10  # seconds

def make_request(method,
                 target,        
                 user=None,
                 pw=None,
                 base_host=None, 
                 headers=None,
                 params=None,    
                 data=None,      
                 json=None,      
                 verify=DEFAULT_VERIFY,
                 timeout=DEFAULT_TIMEOUT,
                 allow_redirects=True,
                 session=None):

    method = method.upper()


    if target.startswith("http://") or target.startswith("https://"):
        url = target
    else:
        if not base_host:
            raise ValueError("target error")

        parsed = urlparse(base_host)
        if not parsed.scheme:
            base_host = "https://" + base_host.rstrip('/')
        url = urljoin(base_host.rstrip('/') + '/', target.lstrip('/'))


    s = session or requests.Session()
    if user is not None and pw is not None:
        s.auth = HTTPDigestAuth(user, pw)


    hdr = {}
    if headers:
        hdr.update(headers)


    if not verify:
        requests.packages.urllib3.disable_warnings()

    try:

        resp = s.request(method=method,
                         url=url,
                         headers=hdr,
                         params=params,
                         data=data,
                         json=json,
                         verify=verify,
                         timeout=timeout,
                         allow_redirects=allow_redirects)

        ret = {
            "ok": resp.ok,
            "status_code": resp.status_code,
            "reason": resp.reason,
            "headers": dict(resp.headers),
            "text": resp.text,
            "url": resp.url,
            "elapsed_seconds": resp.elapsed.total_seconds(),
            "error": None,
        }

        try:
            ret["json"] = resp.json()
        except Exception:
            ret["json"] = None

        return ret

    except requests.RequestException as e:
        return {
            "ok": False,
            "status_code": None,
            "reason": None,
            "headers": None,
            "text": None,
            "json": None,
            "url": url,
            "elapsed_seconds": None,
            "error": str(e),
        }


def make_response_param(user, pw, method, target_path_or_url,
                        base_host=None, headers=None, params=None,
                        data=None, json_body=None, verify=DEFAULT_VERIFY, timeout=DEFAULT_TIMEOUT):
    """

      content = make_response_param("admin","Acs123!!","GET",
                    "/stw-cgi/accesscontrol.cgi?msubmenu=hostcommunication&action=view&SunapiSeqId=124",
                    base_host="192.168.1.160", 
                    headers=..., params=...)
    """
    return make_request(method=method,
                        target=target_path_or_url,
                        user=user, pw=pw, base_host=base_host,
                        headers=headers, params=params, data=data, json=json_body,
                        verify=verify, timeout=timeout)


# ---------------------------
# 사용 예시
# ---------------------------
if __name__ == "__main__":
    TARGET_IP = "192.168.1.160"   # 예시
    USER_ID = "admin"
    USER_PW = "Acs123!!"

    default_headers = {
        "Accept": "application/json",
        "Referer": f"http://{TARGET_IP}",
        "User-Agent": "python-requests/2.x",
    }

    # 1) GET 예시
    with open("output_urls.txt","r") as f:
        for line in f:
            url = line.strip()
            if not url:
                continue
            try:
                print(url)
                response = make_response_param(USER_ID, USER_PW,
                                "GET",
                                url,
                                base_host=TARGET_IP,
                                headers=default_headers,
                                params=None,
                                verify=False,  # self-signed 허용
                                timeout=10)
                                
                if response is not None :
                    try:
                        print("=====================================\n")
                        print(response.decode("utf-8", errors="replace"))
                        print("=====================================\n")
                    except Exception:
                        print(response)
                    # try:
                    #     print("=====================================\n")
                    #     print("GET =>", resp["status_code"], resp["reason"])
                    #     #print("Headers:", resp["headers"])
                    #     print("Text:\n", resp["text"])  
                    #     print("=====================================\n")
                    # except Exception:
                    # print(response)
            except Exception as e:
                print(f"[!] Error requesting {url[:100]}: {e}")         
                 
    resp = make_response_param(USER_ID, USER_PW,
                                "GET",
                                "http://192.168.1.160//stw-cgi/network.cgi?msubmenu=bonjour&action=set&Enable=True&FriendlyName=WISENET-NHP-P200-000918E2797D%3bid&SunapiSeqId=58",
                                base_host=TARGET_IP,
                                headers=default_headers,
                                params=None,
                                verify=False,  # self-signed 허용
                                timeout=10)
    print("GET =>", resp["status_code"], resp["reason"])
    print("Headers:", resp["headers"])
    print("Text:\n", resp["text"])  # 길면 잘라서 출력
    
    
    
    # 2) POST 예시: form data (application/x-www-form-urlencoded)
    '''
    post_headers = default_headers.copy()
    post_headers["Content-Type"] = "application/x-www-form-urlencoded"
    form_data = {
        "param1": "value1",
        "param2": "value2",
    }
    resp2 = make_response_param(USER_ID, USER_PW,
                                "POST",
                                "/stw-cgi/some_post_endpoint.cgi",
                                base_host=TARGET_IP,
                                headers=post_headers,
                                data=form_data,   # form-encoded
                                verify=False,
                                timeout=10)
    print("POST(form) =>", resp2["status_code"], resp2["reason"])
    print("Text:", resp2["text"][:400])

    # 3) POST 예시: JSON body
    post_headers2 = default_headers.copy()
    post_headers2["Content-Type"] = "application/json"
    json_payload = {"key": "value"}
    resp3 = make_response_param(USER_ID, USER_PW,
                                "POST",
                                "/stw-cgi/some_json_endpoint.cgi",
                                base_host=TARGET_IP,
                                headers=post_headers2,
                                json_body=json_payload,  # requests will set body and content-type
                                verify=False,
                                timeout=10)
    print("POST(json) =>", resp3["status_code"], resp3["reason"])
    print("JSON response:", resp3["json"])
    '''