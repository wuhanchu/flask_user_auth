# coding: utf-8

from sqlalchemy import Column, ForeignKey
from sqlalchemy.dialects.mysql import INTEGER
from sqlalchemy.orm import relationship, foreign, remote

from frame.extension.database import db, BaseModel, db_schema
from module.permission.model import PermissionScope
from module.role.model import Role


class User(db.Model):
    __tablename__ = 'user'
    __table_args__ = {'schema': 'user_auth'}

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(40), unique=True)

    def __str__(self):
        if self.name:
            return self.name
        else:
            return "用户"

    def get_user_id(self):
        return self.id

    def check_password(self, password):
        return password == 'valid'

class UserRole(BaseModel, db.Model):
    __tablename__ = 'user_role'

    id = Column(INTEGER(11), primary_key=True)
    user_id = Column(ForeignKey(db_schema + '.user.id'), index=True)
    role_id = Column(ForeignKey(db_schema + '.role.id'), index=True)

    role = relationship('Role',
                        primaryjoin=remote(Role.id) == foreign(role_id))
    user = relationship('User',
                        primaryjoin=remote(User.id) == foreign(user_id))
