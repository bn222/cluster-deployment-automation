import base64
import json


def encode_to_base64(input_string: str) -> str:
    input_bytes = input_string.encode('utf-8')
    encoded_bytes = base64.b64encode(input_bytes)
    return encoded_bytes.decode('utf-8')


def prep_contents(user: str, token: str) -> str:
    value = encode_to_base64(user + ":" + token)
    ret = {"auths": {"registry.ci.openshift.org": {"auth": value}}}
    return json.dumps(ret)


def prep_auth(user: str, token: str) -> None:
    with open("/run/user/0/containers/auth.json", "w") as f:
        f.write(prep_contents(user, token))
