import hashlib
import json

from flask import Flask, render_template, request, jsonify,g,session,Blueprint
from flaskbp.Tool import *
tool = Tool()
col = tool.col
col2 = tool.col2

bp = Blueprint('accountbp',__name__)

# 登录页面**********************************************************************************************账户管理*****************
@bp.route('/login')
def login():
    return render_template('login.html')


# 登录验证用户名和密码是否正确，如果正确就返回到主页面，如果不正确就继续重新加载登录页面
@bp.route('/check', methods=['POST'])
def check():
    user = request.form.get('user')
    password = request.form.get('password')
    h = hashlib.md5()
    h.update(password.encode('utf8'))
    password = h.hexdigest()
    info = {"name":user,"pass":password}
    if col2.count_documents(info) != 0:
        flag = "1"
    else:
        flag = "0"
    session["flag"] = flag
    return flag

# 对管理员用户的添加和修改
@bp.route('/update')
def update():

    return render_template('update.html')


@bp.route('/modify', methods=['POST'])
def modify():
    user = request.form.get('user')
    password = request.form.get('password')
    h = hashlib.md5()
    h.update(password.encode('utf8'))
    password = h.hexdigest()
    info = {"name": user, "pass": password}
    if col2.count_documents({"name":user}) != 0:
        col2.update_one({"name":user},{"$set":{"pass":password}})
    else:
        col2.insert_one(info)
    return "1"




@bp.route('/logout')
def logout():
    session["flag"] = "0"
    return render_template('index.html')