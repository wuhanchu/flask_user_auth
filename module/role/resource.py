# -*- coding:utf-8 -*-
import time

from flask import request

from frame import permission_context
from frame.extension.database import db
from frame.http.response import JsonResult
from frame.util import sql_tool, param_tool
from module.auth.extension.oauth2 import require_oauth
from module.permission.model import Permission, PermissionScopeRetail, PermissionScope
from module.role.model import Role, RolePermissionScope
from . import blueprint


# 角色列表
@blueprint.route('', methods=['GET'])
@require_oauth('profile')
def role_list():
    id = request.args.get("id")
    if id:
        return get_role(id)

    q = Role.query
    name = request.args.get("name")
    if name is not None:
        q = q.filter(Role.name.like("%" + name + "%"))
    q = q.order_by(Role.name.desc())
    offset = int(request.args.get('offset'))
    limit = int(request.args.get('limit'))
    sort = request.args.get('sort')
    if sort == None:
        sort = "-id"
    res, total = sql_tool.model_page(q, limit, offset, sort)
    return JsonResult.res_page(res, total)


def get_role(id):
    """
    # 详细角色信息
    :param id:
    :return:
    """
    obj = Role.query.get(id)
    return JsonResult.queryResult(obj)


@blueprint.route('', methods=['POST'])
@require_oauth('profile')
def add_role():
    obj = Role()
    args = request.get_json()
    # 将参数加载进去
    param_tool.set_dict_parm(obj, args)
    obj.opr_at = int(time.time())
    db.session.add(obj)
    db.session.commit()
    return JsonResult.success("创建成功！", {"id": obj.id})


# PUT:全部字段 ；PATCH:部分字段
@blueprint.route('', methods=['PATCH'])
@require_oauth('profile')
def update_role():
    id = request.args.get("id")
    obj = Role.query.get(id)
    if obj is None:
        return JsonResult.error("对象不存在，id=%s" % id)
    args = request.get_json()
    if "password" in args:
        args.pop("password")
    # 将参数加载进去
    param_tool.set_dict_parm(obj, args)
    db.session.commit()
    return JsonResult.success("更新成功！", {"id": obj.id})


@blueprint.route('', methods=['DELETE'])
@require_oauth('profile')
def del_role():
    """
    删除角色
    :param id:
    :return:
    """
    id = request.args.get("id")
    obj = Role.query.get(id)
    db.session.delete(obj)
    # sql = """ delete from ts_meetasr_log where meetid='%s' """ % meetid
    # db.session.execute(sql)
    db.session.commit()
    return JsonResult.success("删除成功！", {"id": id})


@blueprint.route('/permission', methods=['GET'])
@require_oauth('profile')
def role_permissions_list():
    role_id = request.args.get("role_id")
    q = Permission.query.join(PermissionScopeRetail, PermissionScopeRetail.permission_key == Permission.key) \
        .join(RolePermissionScope,
              RolePermissionScope.permission_scope_key == PermissionScopeRetail.permission_scope_key) \
        .filter(RolePermissionScope.role_id == role_id)
    list = q.all()
    return JsonResult.queryResult(list)


@blueprint.route('/permission_scope', methods=['GET'])
@require_oauth('profile')
def role_permission_scopes_list():
    role_id = request.args.get("role_id")

    q = PermissionScope.query.join(RolePermissionScope,
                                   RolePermissionScope.permission_scope_key == PermissionScope.key) \
        .filter(RolePermissionScope.role_id == role_id)
    list = q.all()
    return JsonResult.queryResult(list)


@blueprint.route('/permission_scope', methods=['PUT'])
def update_role_permission_scopes():
    id = request.args.get("id")

    args = request.get_json()

    # delete before
    db.session.execute(RolePermissionScope.__table__.delete().where(RolePermissionScope.role_id == id))

    # add new
    role_permission_scope = args.get("role_permission_scope")
    for permission_scope in role_permission_scope:
        role_permission_scope = RolePermissionScope(role_id=id, permission_scope_key=permission_scope.get("key"),
                                                    product_key=permission_scope.get("product_key"))
        db.session.add(role_permission_scope)

    db.session.commit()

    # reload
    permission_context.load_permission()
    return JsonResult.success("更新角色权限成功！")


def init_app(app, **kwargs):
    app.register_blueprint(blueprint)
