# -*- coding: UTF-8 -*-

from authlib.oauth2 import OAuth2Error
from flask import render_template, redirect, url_for
from flask import request, session
from werkzeug.security import gen_salt

from module.auth.extension.oauth2 import authorization
from . import blueprint

from module.auth.model import OAuth2Client,db
from ..user.resource import User

def current_user():
    if 'id' in session:
        uid = session['id']
        return User.query.get(uid)
    return None

@blueprint.route('', methods=('GET', 'POST'))
def home():
    if request.method == 'POST':
        username = request.form.get('username')
        user = User.query.filter_by(name=username).first()
        if not user:
            user = User(name=username)
            db.session.add(user)
            db.session.commit()
        session['id'] = user.id
        return redirect(url_for('auth.home'))
    user = current_user()
    if user:
        clients = OAuth2Client.query.filter_by(user_id=user.id).all()
    else:
        clients = []
    return render_template('home.html', user=user, clients=clients)


@blueprint.route('/token', methods=('DELETE',))
@blueprint.route('/logout')
def logout():
    del session['id']
    return redirect(url_for('auth.home'))


@blueprint.route('/create_client', methods=('GET', 'POST'))
def create_client():
    """注册客户端"""
    user = current_user()
    if not user:
        return redirect(url_for('auth.home'))
    if request.method == 'GET':
        return render_template('create_client.html')
    client = OAuth2Client(**request.form.to_dict(flat=True))
    client.user_id = user.id
    client.client_id = gen_salt(24)

    if client.token_endpoint_auth_method == 'none':
        client.client_secret = ''
    else:
        client.client_secret = gen_salt(48)
    db.session.add(client)
    db.session.commit()
    return redirect(url_for('auth.home'))

# 跳转到授权页面
@blueprint.route('/authorize', methods=['GET', 'POST'])
def authorize():
    """对用户进行状态保持查询，此处应该查询token，这里的user 必须是在我们网站注册过客户端的用户"""
    user = current_user()
    if request.method == 'GET':
        # 发送账号密码
        # 接收用户信息，校验信息
        try:
            grant = authorization.validate_consent_request(end_user=user)
        except OAuth2Error as error:
            return error.error
        return render_template('authorize.html', user=user, grant=grant)
    if not user and 'username' in request.form:
        """在客户端没有授权的情况下，客户端应停止，重新登录，然后在进行第三方登录，这里只是简易登录方式"""
        username = request.form.get('username')
        user = User.query.filter_by(name=username).first()
    if request.form['confirm']:
        """如果有用户登录注册过，这里是查询我们网站的注册用户的信息，查询无误后授权给用户授权成功可以登录"""
        # todo
        grant_user = user
    else:
        grant_user = None
    return authorization.create_authorization_response(grant_user=grant_user)

# 令牌端认证
@blueprint.route('/token', methods=['POST'])
def issue_token():
    return authorization.create_token_response()


@blueprint.route('/revoke', methods=['POST'])
def revoke_token():
    return authorization.create_endpoint_response('revocation', request)
