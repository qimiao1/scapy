import geoip2.database

import dns
from flask import Flask, render_template, redirect, request, jsonify,g,session,Blueprint
import time,datetime
from pyecharts import options as opts
from pyecharts.charts import Bar, Geo, Line, Pie
from pyecharts.globals import ChartType, SymbolType
from flaskbp.Tool import *
tool = Tool()
col = tool.col
col2 = tool.col2
bp = Blueprint('singleuserbp',__name__)


# 详细记录***************************************************************************单个用户单个用户单个用户*******************************
@bp.route('/singleUser')
def single_user():
    return render_template('singleUser2.html')


# 向select组件中添加选项
@bp.route('/selectuser')
def get_select_user():
    users = col.distinct("user")
    # 必须返回一个字典
    dict = {}
    for i in range(len(users)):
        dict[i] = users[i]
    return dict


# 获取单个用户的会话详情图
@bp.route("/account")
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
        user = col.find_one()["user"]
    if begintime is None:
        begintime = ""
    if successtime is None:
        successtime = ""
    # 1.    用户名不为空，开始时间为空 ,上报时间为空
    if (begintime == "") & (successtime == ""):
        res = col.aggregate([{"$match": {"user": user}}
                                  , {"$group": {"_id": "$appPro", "count": {"$sum": 1}}}])
        # 2.    用户名不为空，开始时间为空, 上报时间不空
    if (begintime == "") & (successtime != ""):
        # 对上报时间进行解析
        begin, end = parseTime(successtime)

        res = col.aggregate([{"$match": {"user": user, "successTime": {"$gte": begin, "$lte": end}}}
                                  , {"$group": {"_id": "$appPro", "count": {"$sum": 1}}}])
        # 3.    用户名不为空，开始时间不空 ,上报时间为空
    if  (begintime != "") & (successtime == ""):
        # 对开始时间进行解析

        begin, end = parseTime(begintime)
        res = col.aggregate([{"$match": {"user": user, "startTime": {"$gte": begin, "$lte": end}}}
                                  , {"$group": {"_id": "$appPro", "count": {"$sum": 1}}}])
        # 4.    用户名不为空，开始时间不空, 上报时间不空
    if  (begintime != "") & (successtime != ""):
        # 对开始时间进行解析
        begin1, end1 = parseTime(begintime)
        begin2, end2 = parseTime(successtime)
        res = col.aggregate([{"$match": {"user": user, "startTime": {"$gte": begin1, "$lte": end1}
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
@bp.route('/detail')
def get_detail():
    user = request.args.get("user")
    begintime = request.args.get("beginTime")
    successtime = request.args.get("successTime")
    # 如果没有指定用户，那么就返回第一个用户
    if (user is None) | (user == "-1") | (user == ""):
        user = col.find_one()["user"]
    if begintime is None:
        begintime = ""
    if successtime is None:
        successtime = ""
    # 获取该user的详情
    # 这里开始四种情况
    # 1.    用户名不为空，开始时间为空 ,上报时间为空
    if (begintime == "") & (successtime == ""):
        # 数据详情
        nums = col.count_documents({"user": user})
        res = tool.get_user_detail(user)
        # 2.    用户名不为空，开始时间为空, 上报时间不空
    if (begintime == "") & (successtime != ""):
        # 对上报时间进行解析

        begin, end = parseTime(successtime)
        nums = col.count_documents({"user": user, "successTime": {"$gte": begin, "$lte": end}})
        res = tool.get_timezone_detail(user,begin,end)
        # 3.    用户名不为空，开始时间不空 ,上报时间为空
    if (begintime != "") & (successtime == ""):
        # 对开始时间进行解析

        begin, end = parseTime(begintime)
        nums = col.count_documents({"user": user, "startTime": {"$gte": begin, "$lte": end}})
        res = tool.get_timezone_detail(user,begin,end)
        # 4.    用户名不为空，开始时间不空, 上报时间不空
    if  (begintime != "") & (successtime != ""):
        # 对开始时间进行解析

        begin1, end1 = parseTime(begintime)
        begin2, end2 = parseTime(successtime)
        nums = col.count_documents({"user": user, "startTime": {"$gte": begin1, "$lte": end1}
                                       , "successTime": {"$gte": begin2, "$lte": end2}})
        res = tool.get_timezone_detail2(user,begin1,end1,begin2,end2)


    details = []
    for r in res:
        details.append(r)
    cols = {"code": 0, "msg": "", "count": nums, "data": details}
    return cols



# 获取单个用户的目的IP图
@bp.route("/geo_ip")
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
        user = col.find_one()["user"]
    if begintime is None:
        begintime = ""
    if successtime is None:
        successtime = ""
        # 在这里进行判断，应该用什么样的查询语句
        # 1.    用户名不为空，开始时间为空 ,上报时间为空
    place = col.find_one({"user": user}, {"place": 1})["place"]
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
        ip1 = col.find({"user": user}, {"srcIP": 1})
        ip2 = col.find({"user": user}, {"desIP": 1})

        # 2.    用户名不为空，开始时间为空, 上报时间不空
    if (user != "") & (begintime == "") & (successtime != ""):
        # 对上报时间进行解析
        begin, end = parseTime(successtime)
        ip1 = col.find({"user": user, "successTime": {"$gte": begin, "$lte": end}}, {"srcIP": 1})
        ip2 = col.find({"user": user, "successTime": {"$gte": begin, "$lte": end}}, {"desIP": 1})
        # 3.    用户名不为空，开始时间不空 ,上报时间为空
    if (user != "") & (begintime != "") & (successtime == ""):
        # 对开始时间进行解析
        begin, end = parseTime(begintime)
        ip1 = col.find({"user": user, "startTime": {"$gte": begin, "$lte": end}}, {"srcIP": 1})
        ip2 = col.find({"user": user, "startTime": {"$gte": begin, "$lte": end}}, {"desIP": 1})
        # 4.    用户名不为空，开始时间不空, 上报时间不空
    if (user != "") & (begintime != "") & (successtime != ""):
        # 对开始时间进行解析
        begin1, end1 = parseTime(begintime)
        begin2, end2 = parseTime(successtime)
        ip1 = col.find({"user": user, "startTime": {"$gte": begin1, "$lte": end1}
                           , "successTime": {"$gte": begin2, "$lte": end2}}, {"srcIP": 1})
        ip2 = col.find({"user": user, "startTime": {"$gte": begin1, "$lte": end1}
                           , "successTime": {"$gte": begin2, "$lte": end2}}, {"desIP": 1})
    ip = set()
    for r in ip1:
        ip.add(r["srcIP"])
    for r in ip2:
        ip.add(r["desIP"])

    ips = list(ip)
    places = get_place_by_IP(ips)
    return places


def get_place_by_IP(ips):
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
@bp.route('/query')
def query():
    # 首先获取所有的筛选条件
    user = request.args.get('user')
    begintime = request.args.get('beginTime')
    successtime = request.args.get('successTime')
    # 在这里进行判断，应该用什么样的查询语句
    # 1.    用户名不为空，开始时间为空 ,上报时间为空
    if (user != "") & (begintime == "") & (successtime == ""):
        # 会话数量
        nums = col.count_documents({"user": user})

    # 2.    用户名不为空，开始时间为空, 上报时间不空
    if (user != "") & (begintime == "") & (successtime != ""):
        # 对上报时间进行解析
        begin, end = parseTime(successtime)
        nums = col.count_documents({"user": user, "successTime": {"$gte": begin, "$lte": end}})
    # 3.    用户名不为空，开始时间不空 ,上报时间为空
    if (user != "") & (begintime != "") & (successtime == ""):
        # 对开始时间进行解析
        begin, end = parseTime(begintime)
        nums = col.count_documents({"user": user, "startTime": {"$gte": begin, "$lte": end}})
    # 4.    用户名不为空，开始时间不空, 上报时间不空
    if (user != "") & (begintime != "") & (successtime != ""):
        # 对开始时间进行解析
        begin1, end1 = parseTime(begintime)
        begin2, end2 = parseTime(successtime)

        nums = col.count_documents({"user": user, "startTime": {"$gte": begin1, "$lte": end1}
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


@bp.route('/beginTime')
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
    nums = col.count_documents({"startTime":{'$gte':begin},"endTime":{'$lte':end}})
    # 得到这个时间段内的会话占比
    return "1"




