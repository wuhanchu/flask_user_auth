# -*- coding: UTF-8 -*-

from flask import request, abort
from flask_restplus._http import HTTPStatus

from frame.extension.database import db
from frame.http.response import JsonResult
from frame.util.db import auto_commit
from module.license.util import create_license
from . import blueprint, util
from .model import License


@blueprint.route('', methods=['POST'])
@auto_commit(db.session)
def license_upload():
    """
     证书控制 - 上传证书文件
    :return:
    """
    file = request.files.get("license")
    content = file.read()
    file.close()

    is_allow, info = util.check_license(content)
    if is_allow:
        record = License(product_key=info["product_key"], content=content.decode())
        db.session.merge(record)

        return JsonResult.success("注册成功")
    else:
        return JsonResult.error("注册失败，%s" % info), HTTPStatus.FORBIDDEN


@blueprint.route('/file', methods=['POST'])
def license_create():
    """
    证书验证
    :return:
    """
    params = request.json

    return create_license(params.get("machine"), params.get("product_key"), params.get("due_time"),
                          params.get("custom_name"))


@blueprint.route('', methods=['GET'])
def license_info():
    """
     查看证书信息
    :return:
    """
    product_key = request.args.get("product_key")

    record = None
    if product_key:
        record = License.query.get(product_key)

    # 判断证书是否存在，如果存在就返回有效时间
    if record:
        is_enable, msg = util.check_license(record.content)
        if is_enable:
            return JsonResult.success("证书有效！", dict(msg,
                                                    machine_info=util.get_machine_info()))
        else:
            res = {
                "machine_info": util.get_machine_info(),
            }
            return JsonResult.error("%s ，请联系相关销售进行申请证书！" % msg, res)
    else:
        res = {
            "machine_info": util.get_machine_info()
        }
        return JsonResult.error("证书不存在，请联系相关销售进行申请证书！", res)


@blueprint.route('/check', methods=['get'])
def license_check():
    """
    证书验证
    :return:
    """
    product_key = request.args.get("product_key")
    record = License.query.get(product_key)

    if not record or not util.check_license(record.content)[0]:
        abort(HTTPStatus.UNAUTHORIZED, {"message": "证书无效，请联系管理员更新!"})
    return "证书有效"
