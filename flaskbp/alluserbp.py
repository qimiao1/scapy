import geoip2.database

from flask import Flask, render_template,Blueprint
import time,datetime
from pyecharts import options as opts
from pyecharts.charts import Bar, Geo, Line, Pie
from pyecharts.globals import ChartType, SymbolType
from flaskbp.Tool import *
tool = Tool()
col = tool.col
col2 = tool.col2

bp = Blueprint('alluserbp',__name__)

# 采集概况******************************************************************************全体用户全体用户全体用户*************
@bp.route('/allUser')
def all_user():
    return render_template('allUser.html')


@bp.route('/nowflow')
def get_now_flow():
    # 获取当前时刻的上报流量 3600秒是一个小时，那么60就是一分钟，一秒就是1
    now = int(time.time())-10
    res = tool.get_now_flow(now)
    details = []
    for r in res:
        details.append(r)
    cols = {"code":0,"msg":"","count":0,"data":details}
    return cols


# 获取全体用户的总的交互图
@bp.route("/geo_line")
def get_geo_line():
    c = geo_line()
    return c.dump_options_with_quotes()


# 探针交互图
def get_total_IP(user):
    ip1 = col.find({"user": user}, {"srcIP": 1})
    ip2 = col.find({"user": user}, {"desIP": 1})
    ip = set()
    for r in ip1:
        ip.add(r["srcIP"])
    for r in ip2:
        ip.add(r["desIP"])

    ips = list(ip)
    places = get_place_byIP(ips)
    return places

def geo_line() -> Bar:
    users = col.distinct("user")
    list_place = []
    for user in users:
        place = col.find_one({"user": user}, {"place": 1})["place"]
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
@bp.route("/rank1")
def get_rank1():
    # 得到流数排名的前三名
    res = tool.get_flow_rank()
    dict = {}
    i = 1
    for r in res:
        dict[i] = r["user"]+" "+r["place"]+" "+str(r["count"])
        i += 1
    return dict

@bp.route('/rank2')
def get_rank2():
    # 得到包数排名的前三名
    res = tool.get_packet_rank()
    dict = {}
    i = 4
    for r in res:
        dict[i] = r["user"]+"   "+r["place"]+"   "+str(r["count"])
        i += 1
    return dict


# 获取通信总量
@bp.route("/total_num")
def get_total_num():
    c = total_line()
    return c.dump_options_with_quotes()


def total_line() -> Bar:
    now = int(time.time())
    week_ag0 = now - 86400 * 9
    l1,l2 = get_flow_nums(now,week_ag0)
    l3 = get_packet_nums(now,week_ag0)

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
def get_flow_nums(now,week_ago):
    oringal = col.count_documents({"endTime": {'$lte': week_ago}})
    # 获取在这个时间段内每天上报的流数
    res = tool.get_everyday_upload_flow_nums(week_ago,now)
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



def get_packet_nums(now,week_ago):
    # 获取该时间点之前的包数
    oringal = tool.get_previous_upload_nums(week_ago)
    orign = 0
    for o in oringal:
        orign = o["count"]
    # 获取在指定时间之内每天的上报的包数
    res = tool.get_everyday_upload_packet_nums(week_ago,now)

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
