from flask import request

from frame import permission_context
from frame.http.response import JsonResult
from frame.util import param_tool, sql_tool
from module.auth.extension.oauth2 import require_oauth
from .. import blueprint
from ..model import *


# 权限分组列表


@blueprint.route('/scope', methods=['GET'])
@require_oauth('profile')
def permission_scope_list():
    id = request.args.get("id")
    if id:
        return get_permission_scope(id)

    q = PermissionScope.query
    name = request.args.get("name")
    if name is not None:
        q = q.filter(PermissionScope.name.like("%" + name + "%"))
    q = q.order_by(PermissionScope.name.desc())
    offset = int(request.args.get('offset'))
    limit = int(request.args.get('limit'))
    sort = request.args.get('sort')
    if sort == None:
        sort = "-id"
    res, total = sql_tool.model_page(q, limit, offset, sort)
    return JsonResult.res_page(res, total)


# 详细信息
def get_permission_scope(id):
    obj = PermissionScope.query.get(id)
    return JsonResult.queryResult(obj)


# 添加
@blueprint.route('/scope', methods=['POST'])
@require_oauth('profile')
def add_permission_scope():
    obj = PermissionScope()
    args = request.get_json()
    # 将参数加载进去
    param_tool.set_dict_parm(obj, args)
    db.session.add(obj)
    db.session.commit()
    return JsonResult.success("创建成功！", {"id": obj.id})


# 更新， PUT:全部字段 ；PATCH:部分字段
@blueprint.route('/scope/<id>', methods=['PATCH'])
@require_oauth('profile')
def update_permission_scope(id):
    obj = PermissionScope.query.get(id)
    if obj is None:
        return JsonResult.error("对象不存在，id=%s" % id)
    args = request.get_json()
    # 将参数加载进去
    param_tool.set_dict_parm(obj, args)
    db.session.commit()
    return JsonResult.success("更新成功！", {"id": obj.id})


@blueprint.route('/scope', methods=['DELETE'])
@require_oauth('profile')
def del_permission_scope(id):
    """
    删除
    :param id:
    :return:
    """
    permission_scope_key = request.args.get("id")

    obj = PermissionScope.query.get(id)
    db.session.delete(obj)
    # sql = "delete from ts_meetasr_log where meetid='%s' " % meetid
    # db.session.execute(sql)
    db.session.commit()
    return JsonResult.success("删除成功！", {"id": id})


@blueprint.route('/scope/detail', methods=['GET'])
@require_oauth('profile')
def get_group_permissions():
    permission_scope_key = request.args.get("permission_scope_key")
    q = Permission.query.join(PermissionScopeRetail,
                              PermissionScopeRetail.permission_key == Permission.key) \
        .filter(PermissionScopeRetail.permission_scope_key == permission_scope_key)
    list = q.all()
    return JsonResult.queryResult(list)


@blueprint.route('/scope/detail', methods=['PUT'])
@require_oauth('profile')
def update_group_permissions():
    args = request.get_json()
    permission_scope_key = request.args.get("permission_scope_key")
    permission_keys = args.get("permission_keys")
    group_permissions = PermissionScopeRetail.query.filter(
        PermissionScopeRetail.permission_scope_key == permission_scope_key).all()
    for permission_key in permission_keys:
        # 判断数据库中是否已经存在该用户
        selected = [pr for pr in group_permissions if pr.permission_key == permission_key]
        if len(selected) == 0:
            role_permission = PermissionScopeRetail(permission_scope_key=permission_scope_key,
                                                    permission_key=permission_key)
            db.session.add(role_permission)
        else:  # 已存在的角色，从user_roles中删掉，剩下的是要删除的用户
            group_permissions.remove(selected[0])
    # 删除已经不存在的数据
    [db.session.delete(group_permission) for group_permission in group_permissions]
    db.session.commit()
    permission_context.load_permission()
    return JsonResult.success("更新权限分组成功！")
