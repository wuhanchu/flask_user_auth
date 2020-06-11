import jwt
import datetime

from flask import request, g
from flask.json import jsonify
from jwt import exceptions

from run import app

JWT_SALT = 'TESTS'
"""
这是一个JWT认证demon

"""

def create_token(payload, timeout=7200):
    """
    加密
    :param payload:
    :param timeout:
    :return:
    """
    headers = {
        "typ":"jwt",
        "alg":"HS256"
    }
    payload['exp'] = datetime.datetime.utcnow() + datetime.timedelta(minutes=timeout)
    result = jwt.encode(payload=payload, key=JWT_SALT, algorithm="HS256", headers=headers).decode("utf-8")

    return result


def parse_payload(token):
    """
    解密
    :param token:
    :return:
    """
    result = {"status":False, "data":None, "error":None}
    try:
        verified_payload = jwt.decode(token, JWT_SALT, True)
        result["status"] = True
        result["data"] = verified_payload
    except exceptions.ExpiredSignatureError:
        result['error'] = "token已失效"
    except jwt.DecodeError:
        result['error'] = "token认证失败"
    except jwt.InvalidTokenError:
        result['error'] = "非法的token"
    return result

@app.before_request
def jwt_authorization_auth():
    """每次请求进入视图函数之前会执行此函数，验证token"""
    if request.path == '/login/':
        return
    authorization = request.headers.get('Authorization', '')
    auth = authorization.split()
    if not auth:
        return jsonify({'error': '未获取到Authorization请求头', 'status': False})
    if auth[0].lower() != 'jwt':
        return jsonify({'error': 'Authorization请求头中认证方式错误', 'status': False})

    if len(auth) == 1:
        return jsonify({'error': "非法Authorization请求头", 'status': False})
    elif len(auth) > 2:
        return jsonify({'error': "非法Authorization请求头", 'status': False})

    token = auth[1]
    result = parse_payload(token)
    if not result['status']:
        return jsonify(result)
    g.user_info = result['data']

"""
当首次登陆的时候我们需要给客户端发放token
"""
@app.route("/login/",methods=['POST'])
def login():
    """登陆，密码正确返回token"""
    user = request.form.get("username")
    pwd = request.form.get("password")
    if user == "xjk" and pwd == "123":
        token = create_token({"username":"xjk"})
        return jsonify({"status":True,"token":token})
    return jsonify({"status":False,"error":"用户名密码错误"})

