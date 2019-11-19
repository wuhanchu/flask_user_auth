import os,base64
from webapi import baseRoute
from flask import request
from lib.JsonResult import JsonResult
from lib import register_tool

# 证书控制 - 上传证书文件
@baseRoute.route('/register/file', methods=['POST'])
def license_upload():
    licfile = request.files.get("license")
    license = licfile.read()
    licfile.close()
    info = base64.b64decode(license)
    is_allow,info =  register_tool.check_license(info)
    if is_allow:
        with open("./license","wb") as f:
            f.write(license)
        return JsonResult.success("注册成功")
    else:
        return JsonResult.error("注册失败，证书格式错误")

# 证书控制 - 查看证书信息
@baseRoute.route('/register/license', methods=['GET'])
def license_info():
    # 判断证书是否存在，如果存在就返回有效时间
    if os.path.exists("./license"):
        with open("./license") as lic :
            lic_info = lic.read()
            lic_info = base64.b64decode(lic_info)
            is_enable,lic_info = register_tool.check_license(lic_info)
            if is_enable:
                return JsonResult.success("证书有效！", lic_info)
            else:
                res = {
                    "machineInfo": register_tool.get_machineInfo(),
                }
                return JsonResult.error("%，请联系相关销售进行申请证书！"%res , res)

    else:
        res = {
            "machineInfo": register_tool.get_machineInfo()
        }
        return JsonResult.error("证书不存在，请联系相关销售进行申请证书！", res)





