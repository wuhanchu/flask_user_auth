oauth2服务端说明

## 1. init database
初始化数据库MySQL或者postgres数据库，可用表结构初始化如下图

    flask  config 配置项目中需要设置下面的参数
    OAUTH2_REFRESH_TOKEN_GENERATOR = True
    OAUTHLIB_INSECURE_TRANSPORT = True  # # 允许使用HTTP进行OAuth


```
+----------------+
| Tables_in_test |
+----------------+
| oauth2_client  |
| oauth2_code    |
| oauth2_token   |
| user           |
+----------------+
```
## 2. run oauth server
启动服务端任务

## 3. create user and client
在服务端创建用户和客户端，客户端创建时grant_type参数为authorization_code，response_type的参数授权码的为code 这两个字段需要指定不然运行报错

## 4. run client
（1）启动客户端，这里是在oauth2_server文件夹中的client文件夹中的任务，client文件夹在这里作用是测试服务端
（2）在服务端创建用户后在登录状态下，客户端点击login，页面会跳转到服务端，让你授权是否登录，点击consent并且submit
（3）oauth2 验证成功

## 5. Obtain code
当第4步完成后，页面会重新跳转到我们设置的redirect_uri链接上并携带着code

## 6. Obtain token
获取code
设置请求头
headers = {
    "Content-Type":"application/x-www-form-urlencoded",
    "Authorization":"Basic N3N2Rlk0T1FLa1J6MlpzSllrd201WVRQOmtIanFVMllyaHpBeFZUdU5zUzZ0YkdPOFZZSnV5dnhMc0VMMzBlbmtDZmlRSUxXcA=="
}
header请求参数中Authorization的参数组成 Basic + 空格 + client_id:client_secret(需要经过base64加密)

请求参数构造：
params = {
    "grant_type":"authorization_code", # 固定写法
    "redirect_uri":"你的回调网址",
    "client_id":"你的cilent_id",
    "client_secret":"你的client_secret",
    "code":"获取的code"
}
请求方式POST
请求成功后会获得token
{"access_token": "BsVdmoMMJkdq5SfTMm7gOEhe1qFEbhAr8LYrZA37pm", "expires_in": 864000, "scope": "scop", "token_type": "Bearer"}