import pymongo
# 数据库类********************************************************************************************数据库数据库 数据库 数据库***
class Tool():

    myclient = pymongo.MongoClient(
            "mongodb+srv://ws0:1298207618@cluster0.kk8ut.mongodb.net/?retryWrites=true&w=majority")
    db = myclient.test6
    col = db.trafficmodels
    db = myclient.test5
    col2 = db.admin


    def get_user_flows(self,user):
        nums = self.col.count_documents({"name":user})
        return nums


    def get_probe_place(self):
        res = self.col.aggregate([
            {"$group": {"_id": {"place": '$place', "user": '$user'}}},
            {"$group": {"_id": '$_id.place', "count": {"$sum": 1}}},
            {"$project": {"_id": 1, "count": 1}}
        ])
        return res


    def get_upload_tendency(self, week_ago, now):
        res = self.col.aggregate([
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
        res = self.col.aggregate([{"$match": {"user": user}},
                               {"$project": {
                                   "_id": 0, "srcIP": 1, "desIP": 1, "srcPort": 1, "desPort": 1, "protocol": 1,
                                   "appPro": 1, "upNums": 1, "upBytes": 1,  "downNums": 1,  "downBytes": 1,
                                   "place": 1,   "user": 1, 'data': 1,
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
        res = self.col.aggregate([{"$match": {"user": user, "successTime": {"$gte": begin, "$lte": end}}},
                             {"$project": {
                                 "_id": 0, "srcIP": 1, "desIP": 1, "srcPort": 1, "desPort": 1, "protocol": 1,
                                 "appPro": 1,  "upNums": 1, "upBytes": 1, "downNums": 1,
                                 "downBytes": 1, "place": 1, "user": 1,  'data': 1,
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
        res = self.col.aggregate([{"$match": {"user": user, "startTime": {"$gte": begin1, "$lte": end1}
            , "successTime": {"$gte": begin2, "$lte": end2}}},
                             {"$project": {
                                 "_id": 0, "srcIP": 1, "desIP": 1, "srcPort": 1, "desPort": 1, "protocol": 1,
                                 "appPro": 1,   "upNums": 1, "upBytes": 1,
                                 "downNums": 1, "downBytes": 1, "place": 1, "user": 1, 'data': 1,
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
        oringal = self.col.aggregate([{"$match": {"endTime": {'$lte': week_ago}}},
                                 {"$group": {"_id": "", "upcnt": {"$sum": 1}, "downcnt": {"$sum": 1}}},
                                 {"$project": {"count": {"$add": ["$upcnt", "$downcnt"]}}}
                                 ])
        return oringal


    def get_everyday_upload_packet_nums(self,week_ago,now):
        res = self.col.aggregate([
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
        res = self.col.aggregate([
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
        res = self.col.aggregate(
            [{"$group": {"_id": {'user': "$user", 'place': "$place"}, "count": {"$sum": 1}}},
             {'$project': {'_id': 0, 'user': '$_id.user', 'place': '$_id.place', 'count': '$count'}},
             {"$sort": {"count": -1}},
             {"$limit": 3}])
        return  res


    def get_packet_rank(self):
        res = self.col.aggregate(
            [{"$group": {"_id": {'user': "$user", 'place': "$place"}, "upcnt": {"$sum": 1}, "downcnt": {"$sum": 1}}},
             {"$project": {"_id": 0, "user": "$_id.user", "place": "$_id.place",
                           "count": {"$add": ["$upcnt", "$downcnt"]}}},
             {"$sort": {"count": -1}},
             {"$limit": 3}
             ])
        return res

    def get_now_flow(self,now):
        res = self.col.aggregate([{"$match": { "successTime": now}},
                           {"$project": {
                               "_id": 0, "srcIP": 1, "desIP": 1, "srcPort": 1, "desPort": 1, "protocol": 1,
                               "appPro": 1, "data":1,
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