from flask import Flask,  redirect, request, session
from flaskbp import mainbp,alluserbp,singleuserbp,accountbp


app = Flask(__name__)
app.secret_key = '!@#$%^&*()11'

app.register_blueprint(mainbp.bp)
app.register_blueprint(alluserbp.bp)
app.register_blueprint(singleuserbp.bp)
app.register_blueprint(accountbp.bp)
@app.before_request
def before():
    flag = session.get("flag")
    # 进行路径的过滤，如果不是首页，那就跳转到首页
    paths = ['/allUser','/singleUser','/update']
    if (request.path in paths)&(flag != "1"):
        return redirect('/login')

if __name__ == "__main__":

    app.run()
