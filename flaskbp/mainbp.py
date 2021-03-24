import geoip2.database

import dns
from flask import Flask, render_template, redirect, request, jsonify,Blueprint
import time,datetime
from pyecharts import options as opts
from pyecharts.charts import Bar, Geo, Line, Pie
from pyecharts.globals import ChartType, SymbolType

from flaskbp.Tool import *
tool = Tool()
col = tool.col
col2 = tool.col2

bp = Blueprint('mainbp',__name__)

# 概况页：************************************************************************************************首页首页首页首页*****
@bp.route('/')
@bp.route('/index')
def index():
    return render_template('index.html')

# 获取首页里面的探针位置图
@bp.route("/barChart")
def get_bar_chart():
    c = bar_base()
    return c.dump_options_with_quotes()


# 探针位置图
def bar_base() -> Bar:
    res = tool.get_probe_place()
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
@bp.route("/line")
def get_line_chart():
    c = line_base()
    return c.dump_options_with_quotes()


# 上报趋势图
def line_base() -> Bar:
    now = int(time.time())
    week_ago = now - 86400 * 6
    res = tool.get_upload_tendency(week_ago,now)
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
@bp.route('/findNum')
def findNum():
    # 当日凌晨的时间戳
    day_time = int(time.mktime(datetime.date.today().timetuple()))
    todayProbe = len(col.distinct("user",{"endTime": {'$gte': day_time}}))
    todayNum = col.count_documents({"endTime":{'$gte':day_time}})
    probeNum = len(col.distinct("user"))
    dataNum = col.count_documents({})
    num = {"todayProbe":todayProbe,"todayNum":todayNum,"probeNum":probeNum,"dataNum":dataNum}
    return jsonify(num)


