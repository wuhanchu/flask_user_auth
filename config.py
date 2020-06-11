import os

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    # project
    PRODUCT_KEY = "user_auth"
    SECRET_KEY = 'z_markgo'
    SSL_DISABLE = False
    RUN_PORT = os.environ.get('RUN_PORT', 5000)

    # set enable
    ENABLED_EXTENSION = ["loguru", "database", "postgrest", "sentry"]

    # sentry
    SENTRY_DS = "https://c58a597cd1fb4a44b2b719f357325597@server.aiknown.cn:31027/4"

    # auth
    LICENSE_CHECK = False
    # oauth_server
    OAUTH2_REFRESH_TOKEN_GENERATOR = True
    OAUTHLIB_INSECURE_TRANSPORT = True  # # 允许使用HTTP进行OAuth

    # module
    ENABLED_MODULE = [
        'permission',
        'user',
        'role',
        'auth',
        'license'
    ]

    # permission config
    USER_AUTH_LOCAL = True

    # posrgrest
    PROXY_SERVER_URL = os.environ.get('PROXY_SERVER_URL')

    # database
    DB_SCHEMA = "user_auth"
    SQLALCHEMY_ECHO = True
    SQLALCHEMY_RECORD_QUERIES = True
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URI')

    # schedule jobs
    JOBS = [
        {
            'id': 'job_check_item',
            'func': 'extensions.scheduler:job_check_project_item',
            # 'trigger': 'interval',
            # 'seconds': 60,
            'trigger': 'cron',
            'hour': 0,
            'minute': 0,
            'second': 0

        }
    ]

class DevelopmentConfig(Config):
    DEBUG = True
    # set enable
    ENABLED_EXTENSION = ["loguru", "database", "postgrest"]

    RUN_PORT = 5000
    PROXY_SERVER_URL = os.environ.get('PROXY_SERVER_URL', "http://server.aiknown.cn:32023")
    SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URI',
                                             'postgresql://postgres:dataknown1234@server.aiknown.cn:32021/dataknown')


class TestingConfig(Config):
    TESTING = True


class ProductionConfig(Config):
    pass


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
