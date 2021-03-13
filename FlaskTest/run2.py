import geoip2.database
import pymongo
from flask import Flask, render_template, redirect, request, jsonify,g,session
import time,datetime
from pyecharts import options as opts
from pyecharts.charts import Bar, Geo, Line, Pie
from pyecharts.globals import ChartType, SymbolType

app = Flask(__name__)
app.secret_key = '!@#$%^&*()11'
# 在所有的映射之前就开始进行检验，如果咩有登录那就进行登录


@app.before_request
def before():
    # 建立一个数据库连接,并将数据库存入全局变量中
    tool = Tool()
    tool.get_traffic()
    tool.get_admin()
    g.tool = tool
    flag = session.get("flag")
    # 进行路径的过滤，如果不是首页，那就跳转到首页
    paths = ['/allUser','/singleUser','/update']
    if (request.path in paths)&(flag != "1"):
        return redirect('/login')


# 概况页：************************************************************************************************首页首页首页首页*****
@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')

# 获取首页里面的探针位置图
@app.route("/barChart")
def get_bar_chart():
    c = bar_base()
    return c.dump_options_with_quotes()


# 探针位置图
def bar_base() -> Bar:
    res = g.tool.get_probe_place()
    l1 = []
    l2 = []
    for r in res:
        i = 0
        for k, v in r.items():
            if i % 2 == 0:
                l1.append(v)
            else:
                l2.append(v)
            i += 1

    c = (
        Geo()
            .add_schema(maptype="china")
            .add("探针数", [list(t) for t in zip(l1, l2)])
            .set_series_opts(label_opts=opts.LabelOpts(is_show=False))
            .set_global_opts(
            visualmap_opts=opts.VisualMapOpts(max_=200), title_opts=opts.TitleOpts(title="探针的位置"),
                tooltip_opts=opts.TooltipOpts(formatter="{b}:{c}")
        )
    )
    return c


# 获取首页里面的上报趋势图
@app.route("/line")
def get_line_chart():
    c = line_base()
    return c.dump_options_with_quotes()


# 上报趋势图
def line_base() -> Bar:
    now = int(time.time())
    week_ago = now - 86400 * 6
    res = g.tool.get_upload_tendency(week_ago,now)
    l1 = []
    l2 = []
    l3 = []
    for r in res:
        l3.append(r)
    l4 = []
    for x in range(week_ago, now + 1, +86400):
        l4.append(time.strftime("%Y-%m-%d", time.localtime(x)))
    for x in l4:
        flag = False
        for r in l3:
            if r["_id"] == x:
                l1.append(r["_id"])
                l2.append(r["count"])
                flag = True
        if flag == False:
            l1.append(x)
            l2.append(0)
    c = (
        Line()
            .add_xaxis (l1)
            .add_yaxis("每日上报数", l2, is_connect_nones=True)
            .set_global_opts(title_opts=opts.TitleOpts(title="上报趋势"))

    )
    return c


# 查询当前探针总数以及数据总量，需要查询数据库,返回一个json类型的对象给前端
@app.route('/findNum')
def findNum():
    # 当日凌晨的时间戳
    day_time = int(time.mktime(datetime.date.today().timetuple()))
    todayProbe = len(g.col.distinct("user",{"endTime": {'$gte': day_time}}))
    todayNum = g.col.count_documents({"endTime":{'$gte':day_time}})
    probeNum = len(g.col.distinct("user"))
    dataNum = g.col.count_documents({})
    num = {"todayProbe":todayProbe,"todayNum":todayNum,"probeNum":probeNum,"dataNum":dataNum}
    return jsonify(num)




# 采集概况******************************************************************************全体用户全体用户全体用户*************
@app.route('/allUser')
def allUser():
    return render_template('allUser.html')


@app.route('/nowflow')
def get_now_flow():
    # 获取当前时刻的上报流量 3600秒是一个小时，那么60就是一分钟，一秒就是1
    now = int(time.time())-10
    res = g.col.aggregate([{"$match": { "successTime": now}},
                           {"$project": {
                               "_id": 0, "srcIP": 1, "desIP": 1, "srcPort": 1, "desPort": 1, "protocol": 1,
                               "appPro": 1,
                               "upNums": 1, "upBytes": 1, "downNums": 1, "downBytes": 1, "place": 1, "user": 1,
                               "startTime": {"$dateToString": {"format": "%Y-%m-%d %H:%M:%S",
                                                               "date": {
                                                                   "$toDate": {"$multiply": ["$startTime", 1000]}},
                                                               "timezone": "+08:00"}},
                               "endTime": {"$dateToString": {"format": "%Y-%m-%d %H:%M:%S",
                                                             "date": {"$toDate": {"$multiply": ["$endTime", 1000]}},
                                                             "timezone": "+08:00"}},
                               "successTime": {"$dateToString": {"format": "%Y-%m-%d %H:%M:%S",
                                                                 "date": {"$toDate": {
                                                                     "$multiply": ["$successTime", 1000]}},
                                                                 "timezone": "+08:00"}}
                           }
                           }])
    details = []
    for r in res:
        details.append(r)
    cols = {"code":0,"msg":"","count":0,"data":details}
    return cols


# 获取全体用户的总的交互图
@app.route("/geo_line")
def get_geo_line():
    c = geo_line()
    return c.dump_options_with_quotes()


# 探针交互图
def get_total_IP(user):
    ip1 = g.col.find({"user": user}, {"srcIP": 1})
    ip2 = g.col.find({"user": user}, {"desIP": 1})
    ip = set()
    for r in ip1:
        ip.add(r["srcIP"])
    for r in ip2:
        ip.add(r["desIP"])

    ips = list(ip)
    places = get_place_byIP(ips)
    return places

def geo_line() -> Bar:
    users = g.col.distinct("user")
    list_place = []
    for user in users:
        place = g.col.find_one({"user": user}, {"place": 1})["place"]
        places = get_total_IP(user)

        for p in places:
            list_place.append([place, p])
    c = (
        Geo()
            .add_schema(maptype="world")
            .add_coordinate_json(json_file="world_country.json")
            .add(
            "交互图",
            list_place,
            type_=ChartType.LINES,
            effect_opts=opts.EffectOpts(
                symbol=SymbolType.DIAMOND, symbol_size=6, color="blue"
            ),
            linestyle_opts=opts.LineStyleOpts(curve=0.2, opacity=0.2, )
        )
            .set_series_opts(label_opts=opts.LabelOpts(is_show=False))
            .set_global_opts(title_opts=opts.TitleOpts(title="总交互图"), tooltip_opts=opts.TooltipOpts(is_show=True))
    )
    return c




# 获取通信总量的排名
@app.route("/rank1")
def get_rank1():
    # 得到流数排名的前三名
    res = g.tool.get_flow_rank()
    dict = {}
    i = 1
    for r in res:
        dict[i] = r["user"]+" "+r["place"]+" "+str(r["count"])
        i += 1
    return dict

@app.route('/rank2')
def get_rank2():
    # 得到包数排名的前三名
    res = g.tool.get_packet_rank()
    dict = {}
    i = 4
    for r in res:
        dict[i] = r["user"]+"   "+r["place"]+"   "+str(r["count"])
        i += 1
    return dict


# 获取通信总量
@app.route("/total_num")
def get_total_num():
    c = total_line()
    return c.dump_options_with_quotes()


def total_line() -> Bar:
    now = int(time.time())
    week_ag0 = now - 86400 * 9
    l1,l2 = get_flow_nums(g.col,now,week_ag0)
    l3 = get_packet_nums(g.col,now,week_ag0)

    c = (
        Bar()
            .add_xaxis(l1)
            .add_yaxis("每日系统流总量",l2)
            .add_yaxis("每日系统包总量", l3)
            .set_global_opts(
            xaxis_opts=opts.AxisOpts(axislabel_opts=opts.LabelOpts(rotate=-5))
        )

    )
    return c


# 通信总量图
def get_flow_nums(col,now,week_ago):
    oringal = col.count_documents({"endTime": {'$lte': week_ago}})
    # 获取在这个时间段内每天上报的流数
    res = g.tool.get_everyday_upload_flow_nums(week_ago,now)
    l1 = []
    l2 = []
    l3 = []
    for r in res:
        l3.append(r)
    l4 = []
    for x in range(week_ago, now + 1, +86400):
        l4.append(time.strftime("%m-%d", time.localtime(x)))
    sum = oringal
    for x in l4:
        flag = False
        for r in l3:
            if r["_id"] == x:
                l1.append(r["_id"])
                sum += r["count"]
                l2.append(sum)
                flag = True
        if flag == False:
            l1.append(x)
            l2.append(sum)
    return l1,l2



def get_packet_nums(col,now,week_ago):
    # 获取该时间点之前的包数
    oringal = g.tool.get_previous_upload_nums(week_ago)
    orign = 0
    for o in oringal:
        orign = o["count"]
    # 获取在指定时间之内每天的上报的包数
    res = g.tool.get_everyday_upload_packet_nums(week_ago,now)

    l1 = []
    l2 = []
    l3 = []
    for r in res:
        l3.append(r)
    l4 = []
    for x in range(week_ago, now + 1, +86400):
        l4.append(time.strftime("%Y-%m-%d", time.localtime(x)))
    sum = orign
    for x in l4:
        flag = False
        for r in l3:
            if r["_id"] == x:
                l1.append(r["_id"])
                sum += r["count"]
                l2.append(sum)
                flag = True
        if flag == False:
            l1.append(x)
            l2.append(sum)
    return l2



# 详细记录***************************************************************************单个用户单个用户单个用户*******************************
@app.route('/singleUser')
def singleUser():
    return render_template('singleUser.html')


# 向select组件中添加选项
@app.route('/selectuser')
def get_selecct_user():
    users = g.col.distinct("user")
    # 必须返回一个字典
    dict = {}
    for i in range(len(users)):
        dict[i] = users[i]
    return dict


# 获取单个用户的会话详情图
@app.route("/account")
def get_account():
    c = account_pie()
    return c.dump_options_with_quotes()


# 会话占比图
def account_pie() -> Bar:
    # 获取前端的传参user
    user = request.args.get("user")
    begintime = request.args.get("beginTime")
    successtime = request.args.get("successTime")
    # 如果没有指定用户，那么就返回第一个用户
    if (user is None) | (user == "-1") | (user == ""):
        user = g.col.find_one()["user"]
    if begintime is None:
        begintime = ""
    if successtime is None:
        successtime = ""
    # 1.    用户名不为空，开始时间为空 ,上报时间为空
    if (begintime == "") & (successtime == ""):
        res = g.col.aggregate([{"$match": {"user": user}}
                                  , {"$group": {"_id": "$appPro", "count": {"$sum": 1}}}])
        # 2.    用户名不为空，开始时间为空, 上报时间不空
    if (begintime == "") & (successtime != ""):
        # 对上报时间进行解析
        begin, end = parseTime(successtime)

        res = g.col.aggregate([{"$match": {"user": user, "successTime": {"$gte": begin, "$lte": end}}}
                                  , {"$group": {"_id": "$appPro", "count": {"$sum": 1}}}])
        # 3.    用户名不为空，开始时间不空 ,上报时间为空
    if  (begintime != "") & (successtime == ""):
        # 对开始时间进行解析

        begin, end = parseTime(begintime)
        res = g.col.aggregate([{"$match": {"user": user, "startTime": {"$gte": begin, "$lte": end}}}
                                  , {"$group": {"_id": "$appPro", "count": {"$sum": 1}}}])
        # 4.    用户名不为空，开始时间不空, 上报时间不空
    if  (begintime != "") & (successtime != ""):
        # 对开始时间进行解析
        begin1, end1 = parseTime(begintime)
        begin2, end2 = parseTime(successtime)
        res = g.col.aggregate([{"$match": {"user": user, "startTime": {"$gte": begin1, "$lte": end1}
            , "successTime": {"$gte": begin2, "$lte": end2}}}
                                  , {"$group": {"_id": "$appPro", "count": {"$sum": 1}}}])
    l1 = []
    l2 = []
    for r in res:
        i = 0
        for k, v in r.items():
            if i % 2 == 0:
                l1.append(v)
            else:
                l2.append(v)
            i += 1
    l3 = [list(t) for t in zip(l1, l2)]
    c = (
        Pie()
            .add("",  l3,radius="50%,80%")
            .set_global_opts(title_opts=opts.TitleOpts())
            .set_series_opts(label_opts=opts.LabelOpts(formatter="{b}: {c}"))

    )
    return c



# 获取该用户的会话详情
@app.route('/detail')
def get_detail():
    user = request.args.get("user")
    begintime = request.args.get("beginTime")
    successtime = request.args.get("successTime")
    # 如果没有指定用户，那么就返回第一个用户
    if (user is None) | (user == "-1") | (user == ""):
        user = g.col.find_one()["user"]
    if begintime is None:
        begintime = ""
    if successtime is None:
        successtime = ""
    # 获取该user的详情
    # 这里开始四种情况
    # 1.    用户名不为空，开始时间为空 ,上报时间为空
    if (begintime == "") & (successtime == ""):
        # 数据详情
        nums = g.col.count_documents({"user": user})
        res = g.tool.get_user_detail(user)
        # 2.    用户名不为空，开始时间为空, 上报时间不空
    if (begintime == "") & (successtime != ""):
        # 对上报时间进行解析

        begin, end = parseTime(successtime)
        nums = g.col.count_documents({"user": user, "successTime": {"$gte": begin, "$lte": end}})
        res = g.tool.get_timezone_detail(user,begin,end)
        # 3.    用户名不为空，开始时间不空 ,上报时间为空
    if (begintime != "") & (successtime == ""):
        # 对开始时间进行解析

        begin, end = parseTime(begintime)
        nums = g.col.count_documents({"user": user, "startTime": {"$gte": begin, "$lte": end}})
        res = g.tool.get_timezone_detail(user,begin,end)
        # 4.    用户名不为空，开始时间不空, 上报时间不空
    if  (begintime != "") & (successtime != ""):
        # 对开始时间进行解析

        begin1, end1 = parseTime(begintime)
        begin2, end2 = parseTime(successtime)
        nums = g.col.count_documents({"user": user, "startTime": {"$gte": begin1, "$lte": end1}
                                       , "successTime": {"$gte": begin2, "$lte": end2}})
        res = g.tool.get_timezone_detail2(user,begin1,end1,begin2,end2)


    details = []
    for r in res:
        details.append(r)
    cols = {"code": 0, "msg": "", "count": nums, "data": details}
    return cols



# 获取单个用户的目的IP图
@app.route("/geo_ip")
def get_geo_ip():
    c = geo_ip()
    return c.dump_options_with_quotes()


# 目的IP交互图
def geo_ip() -> Bar:
    # 连接数据库
    # 获取前端的传参user
    # 获取前端的传参user
    user = request.args.get("user")
    begintime = request.args.get("beginTime")
    successtime = request.args.get("successtime")
    # 如果没有指定用户，那么就返回第一个用户
    if (user is None) | (user == "-1") | (user == ""):
        user = g.col.find_one()["user"]
    if begintime is None:
        begintime = ""
    if successtime is None:
        successtime = ""
        # 在这里进行判断，应该用什么样的查询语句
        # 1.    用户名不为空，开始时间为空 ,上报时间为空
    place = g.col.find_one({"user": user}, {"place": 1})["place"]
    places = get_all_IP(user, begintime, successtime)
    list_place = []
    for p in places:
        list_place.append([place, p])
    c = (
        Geo()
            .add_schema(maptype="world")
            .add_coordinate_json(json_file="world_country.json")
            .add(
            "目的IP位置",
            list_place,
            type_=ChartType.LINES,
            effect_opts=opts.EffectOpts(
                symbol=SymbolType.DIAMOND, symbol_size=6, color="blue"
            ),
            linestyle_opts=opts.LineStyleOpts(curve=0.2, opacity=0.2, )
        )
            .set_series_opts(label_opts=opts.LabelOpts(is_show=False))
            .set_global_opts(title_opts=opts.TitleOpts(title="目的IP交互图"), tooltip_opts=opts.TooltipOpts(is_show=True))
    )
    return c


def get_all_IP(user,begintime,successtime):
    if (user != "") & (begintime == "") & (successtime == ""):
        ip1 = g.col.find({"user": user}, {"srcIP": 1})
        ip2 = g.col.find({"user": user}, {"desIP": 1})

        # 2.    用户名不为空，开始时间为空, 上报时间不空
    if (user != "") & (begintime == "") & (successtime != ""):
        # 对上报时间进行解析
        begin, end = parseTime(successtime)
        ip1 = g.col.find({"user": user, "successTime": {"$gte": begin, "$lte": end}}, {"srcIP": 1})
        ip2 = g.col.find({"user": user, "successTime": {"$gte": begin, "$lte": end}}, {"desIP": 1})
        # 3.    用户名不为空，开始时间不空 ,上报时间为空
    if (user != "") & (begintime != "") & (successtime == ""):
        # 对开始时间进行解析
        begin, end = parseTime(begintime)
        ip1 = g.col.find({"user": user, "startTime": {"$gte": begin, "$lte": end}}, {"srcIP": 1})
        ip2 = g.col.find({"user": user, "startTime": {"$gte": begin, "$lte": end}}, {"desIP": 1})
        # 4.    用户名不为空，开始时间不空, 上报时间不空
    if (user != "") & (begintime != "") & (successtime != ""):
        # 对开始时间进行解析
        begin1, end1 = parseTime(begintime)
        begin2, end2 = parseTime(successtime)
        ip1 = g.col.find({"user": user, "startTime": {"$gte": begin1, "$lte": end1}
                           , "successTime": {"$gte": begin2, "$lte": end2}}, {"srcIP": 1})
        ip2 = g.col.find({"user": user, "startTime": {"$gte": begin1, "$lte": end1}
                           , "successTime": {"$gte": begin2, "$lte": end2}}, {"desIP": 1})
    ip = set()
    for r in ip1:
        ip.add(r["srcIP"])
    for r in ip2:
        ip.add(r["desIP"])

    ips = list(ip)
    places = get_place_byIP(ips)
    return places


def get_place_byIP(ips):
    reader = geoip2.database.Reader('./GeoLite2-City.mmdb')
    places = set()
    for l in ips:
        try:
            response = reader.city(l)
        except:
            pass
        else:
            country = response.country.names['zh-CN']
            try:
                city = response.city.names['zh-CN']
            except:
                if country == "香港":
                    city = "香港"
                else:
                    city = ""
            finally:
                if (country == "中国") & (city!=""):
                    places.add(city)
                elif country == "香港":
                    places.add(country)
                elif country == "美国":
                    places.add("United States")

    places = list(places)
    return places



# 监听select的选项，得到选项的值，然后进行查询单个用户的会话流量以及会话占比图和会话交互图以及会话详情图
@app.route('/query')
def query():
    # 首先获取所有的筛选条件
    user = request.args.get('user')
    begintime = request.args.get('beginTime')
    successtime = request.args.get('successTime')
    # 在这里进行判断，应该用什么样的查询语句
    # 1.    用户名不为空，开始时间为空 ,上报时间为空
    if (user != "") & (begintime == "") & (successtime == ""):
        # 会话数量
        nums = g.col.count_documents({"user": user})

    # 2.    用户名不为空，开始时间为空, 上报时间不空
    if (user != "") & (begintime == "") & (successtime != ""):
        # 对上报时间进行解析
        begin, end = parseTime(successtime)
        nums = g.col.count_documents({"user": user, "successTime": {"$gte": begin, "$lte": end}})
    # 3.    用户名不为空，开始时间不空 ,上报时间为空
    if (user != "") & (begintime != "") & (successtime == ""):
        # 对开始时间进行解析
        begin, end = parseTime(begintime)
        nums = g.col.count_documents({"user": user, "startTime": {"$gte": begin, "$lte": end}})
    # 4.    用户名不为空，开始时间不空, 上报时间不空
    if (user != "") & (begintime != "") & (successtime != ""):
        # 对开始时间进行解析
        begin1, end1 = parseTime(begintime)
        begin2, end2 = parseTime(successtime)

        nums = g.col.count_documents({"user": user, "startTime": {"$gte": begin1, "$lte": end1}
                                       , "successTime": {"$gte": begin2, "$lte": end2}})

    return {"nums": nums}


def parseTime(timezone):
    print(timezone)
    time_list = timezone.split(' - ')
    begin = time_list[0]
    timeArray = time.strptime(begin, "%Y-%m-%d %H:%M:%S")
    begin = int(time.mktime(timeArray))
    end = time_list[1]
    timeArray = time.strptime(end, "%Y-%m-%d %H:%M:%S")
    end = int(time.mktime(timeArray))
    return begin,end


@app.route('/beginTime')
def begin_time_check():

    beginTime = request.args.get("beginTime")
    time_list = beginTime.split(' - ')
    begin = time_list[0]
    timeArray = time.strptime(begin, "%Y-%m-%d %H:%M:%S")
    begin = int(time.mktime(timeArray))
    end = time_list[1]
    timeArray = time.strptime(end, "%Y-%m-%d %H:%M:%S")
    end = int(time.mktime(timeArray))
    # 得到这个时间段内的会话数量
    nums = g.col.count_documents({"startTime":{'$gte':begin},"endTime":{'$lte':end}})
    # 得到这个时间段内的会话占比
    return "1"





# 登录页面**********************************************************************************************账户管理*****************
@app.route('/login')
def login():
    return render_template('login.html')

# 登录验证用户名和密码是否正确，如果正确就返回到主页面，如果不正确就继续重新加载登录页面
@app.route('/check')
def check():
    user = request.args.get('user')
    password = request.args.get('password')
    info = {"name":user,"pass":password}
    if g.col2.count_documents(info) != 0:
        flag = "1"
    else:
        flag = "0"
    session["flag"] = flag
    return flag



# 对管理员用户的添加和修改
@app.route('/update')
def update():

    return render_template('update.html')


@app.route('/modify')
def modify():
    user = request.args.get('user')
    password = request.args.get('password')
    info = {"name": user, "pass": password}
    if g.col2.count_documents({"name":user}) != 0:
        g.col2.update_one({"name":user},{"$set":{"pass":password}})
    else:
        g.col2.insert_one(info)
    return "1"




@app.route('/logout')
def logout():
    session["flag"] = "0"
    return render_template('index.html')


# 数据库类********************************************************************************************数据库数据库 数据库 数据库***
class Tool():
    def get_traffic(self):
        col = getattr(g, 'col', None)
        if col is None:
            myclient = pymongo.MongoClient(
                "mongodb+srv://ws0:1298207618@cluster0.kk8ut.mongodb.net/?retryWrites=true&w=majority")
            db = myclient.test5
            col = db.trafficmodels
            g.col = col
        return col

    def get_admin(self):
        col2 = getattr(g, 'col2', None)
        if col2 is None:
            myclient = pymongo.MongoClient(
                "mongodb+srv://ws0:1298207618@cluster0.kk8ut.mongodb.net/?retryWrites=true&w=majority")
            db = myclient.test5
            col2 = db.admin
            g.col2 = col2
        return col2


    def get_user_flows(self,user):
        nums = g.col.count_documents({"name":user})
        return nums


    def get_probe_place(self):
        res = g.col.aggregate([
            {"$group": {"_id": {"place": '$place', "user": '$user'}}},
            {"$group": {"_id": '$_id.place', "count": {"$sum": 1}}},
            {"$project": {"_id": 1, "count": 1}}
        ])
        return res


    def get_upload_tendency(self, week_ago, now):
        res = g.col.aggregate([
            {"$match": {"endTime": {'$gte': week_ago, '$lt': now}}},
            {"$project": {"_id": 1,
                          "time": {"$dateToString": {"format": "%Y-%m-%d",
                                                     "date": {"$toDate": {"$multiply": ["$endTime", 1000]}},
                                                     "timezone": "+08:00"}
                                   }
                          }},
            {"$group": {"_id": "$time", "count": {"$sum": 1}}}
        ])
        return res


    def get_user_detail(self,user):
        res = g.col.aggregate([{"$match": {"user": user}},
                               {"$project": {
                                   "_id": 0, "srcIP": 1, "desIP": 1, "srcPort": 1, "desPort": 1, "protocol": 1,
                                   "appPro": 1, "upNums": 1, "upBytes": 1,  "downNums": 1,  "downBytes": 1,
                                   "place": 1,   "user": 1,
                                   "startTime": {"$dateToString": {"format": "%Y-%m-%d %H:%M:%S",
                                                                   "date": {
                                                                       "$toDate": {"$multiply": ["$startTime", 1000]}},
                                                                   "timezone": "+08:00"}},
                                   "endTime": {"$dateToString": {"format": "%Y-%m-%d %H:%M:%S",
                                                                 "date": {"$toDate": {"$multiply": ["$endTime", 1000]}},
                                                                 "timezone": "+08:00"}},
                                   "successTime": {"$dateToString": {"format": "%Y-%m-%d %H:%M:%S",
                                                                     "date": {"$toDate": {
                                                                         "$multiply": ["$successTime", 1000]}},
                                                                     "timezone": "+08:00"}}
                               }
                               }])
        return res


    def get_timezone_detail(self,user,begin,end):
        res = g.col.aggregate([{"$match": {"user": user, "successTime": {"$gte": begin, "$lte": end}}},
                             {"$project": {
                                 "_id": 0, "srcIP": 1, "desIP": 1, "srcPort": 1, "desPort": 1, "protocol": 1,
                                 "appPro": 1,
                                 "upNums": 1, "upBytes": 1, "downNums": 1, "downBytes": 1, "place": 1, "user": 1,
                                 "startTime": {"$dateToString": {"format": "%Y-%m-%d %H:%M:%S",
                                                                 "date": {
                                                                     "$toDate": {"$multiply": ["$startTime", 1000]}},
                                                                 "timezone": "+08:00"}},
                                 "endTime": {"$dateToString": {"format": "%Y-%m-%d %H:%M:%S",
                                                               "date": {"$toDate": {"$multiply": ["$endTime", 1000]}},
                                                               "timezone": "+08:00"}},
                                 "successTime": {"$dateToString": {"format": "%Y-%m-%d %H:%M:%S",
                                                                   "date": {"$toDate": {
                                                                       "$multiply": ["$successTime", 1000]}},
                                                                   "timezone": "+08:00"}}
                             }
                             }])
        return res


    def get_timezone_detail2(self,user,begin1,end1,begin2,end2):
        res = g.col.aggregate([{"$match": {"user": user, "startTime": {"$gte": begin1, "$lte": end1}
            , "successTime": {"$gte": begin2, "$lte": end2}}},
                             {"$project": {
                                 "_id": 0, "srcIP": 1, "desIP": 1, "srcPort": 1, "desPort": 1, "protocol": 1,
                                 "appPro": 1,
                                 "upNums": 1, "upBytes": 1, "downNums": 1, "downBytes": 1, "place": 1, "user": 1,
                                 "startTime": {"$dateToString": {"format": "%Y-%m-%d %H:%M:%S",
                                                                 "date": {
                                                                     "$toDate": {"$multiply": ["$startTime", 1000]}},
                                                                 "timezone": "+08:00"}},
                                 "endTime": {"$dateToString": {"format": "%Y-%m-%d %H:%M:%S",
                                                               "date": {"$toDate": {"$multiply": ["$endTime", 1000]}},
                                                               "timezone": "+08:00"}},
                                 "successTime": {"$dateToString": {"format": "%Y-%m-%d %H:%M:%S",
                                                                   "date": {"$toDate": {
                                                                       "$multiply": ["$successTime", 1000]}},
                                                                   "timezone": "+08:00"}}
                             }
                             }])
        return res





    def get_previous_upload_nums(self,week_ago):
        oringal = g.col.aggregate([{"$match": {"endTime": {'$lte': week_ago}}},
                                 {"$group": {"_id": "", "upcnt": {"$sum": 1}, "downcnt": {"$sum": 1}}},
                                 {"$project": {"count": {"$add": ["$upcnt", "$downcnt"]}}}
                                 ])
        return oringal


    def get_everyday_upload_packet_nums(self,week_ago,now):
        res = g.col.aggregate([
            {"$match": {"endTime": {'$gte': week_ago, '$lt': now}}},
            {"$project": {"_id": 1,
                          "time": {"$dateToString": {"format": "%Y-%m-%d",
                                                     "date": {"$toDate": {"$multiply": ["$endTime", 1000]}},
                                                     "timezone": "+08:00"}
                                   }
                          }},
            {"$group": {"_id": "$time", "upcnt": {"$sum": 1}, "downcnt": {"$sum": 1}}},
            {"$project": {"count": {"$add": ["$upcnt", "$downcnt"]}}}
        ])
        return res

    def get_everyday_upload_flow_nums(self,week_ago,now):
        res = g.col.aggregate([
            {"$match": {"endTime": {'$gte': week_ago, '$lt': now}}},
            {"$project": {"_id": 1,
                          "time": {"$dateToString": {"format": "%m-%d",
                                                     "date": {"$toDate": {"$multiply": ["$endTime", 1000]}},
                                                     "timezone": "+08:00"}
                                   }
                          }},
            {"$group": {"_id": "$time", "count": {"$sum": 1}}}
        ])

        return res

    def get_flow_rank(self):
        res = g.col.aggregate(
            [{"$group": {"_id": {'user': "$user", 'place': "$place"}, "count": {"$sum": 1}}},
             {'$project': {'_id': 0, 'user': '$_id.user', 'place': '$_id.place', 'count': '$count'}},
             {"$sort": {"count": -1}},
             {"$limit": 3}])
        return  res


    def get_packet_rank(self):
        res = g.col.aggregate(
            [{"$group": {"_id": {'user': "$user", 'place': "$place"}, "upcnt": {"$sum": 1}, "downcnt": {"$sum": 1}}},
             {"$project": {"_id": 0, "user": "$_id.user", "place": "$_id.place",
                           "count": {"$add": ["$upcnt", "$downcnt"]}}},
             {"$sort": {"count": -1}},
             {"$limit": 3}
             ])
        return res


if __name__ == "__main__":
    app.run()
