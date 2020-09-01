from docxtpl import DocxTemplate, InlineImage
from docx.shared import Mm
import csv
import re
import argparse
from datetime import datetime
import pytz
from dateutil import parser as dateutil_parser
import plotly.graph_objects as go
import plotly.express as px
# additional packages needed by plotly
import requests
import psutil
import kaleido
##
import numpy as np
import pandas as pd

DEFAULT_TEMPLATE_FILE = 'template.docx'
DEFAULT_REPORT_FILE = 'report.docx'
DEFAULT_META_FILE = 'meta.csv'
DEFAULT_RULES_FILE = 'rules.csv'
DEFAULT_PROTECTORS_FILE = 'protectors.csv'
DEFAULT_EVENTS_FILE = 'events.csv'

DARKTHEME = {"INFO": "#a9a9a9", "LOW": "#70dbed", "MEDIUM": "#eab839", "HIGH": "#890f02"}
CORPTHEME = {"INFO": "#CCCCCC", "LOW": "#483B4C", "MEDIUM": "#FFC502", "HIGH": "#C20000"}
SEVERITYTHEME = {"INFO": "#DDDDDD", "LOW": "#2196F3", "MEDIUM": "#FF9800", "HIGH": "#F44336"}
TOP10THEME = px.colors.qualitative.D3

class Dataset:
    def __init__(self, tpl, args):
        def read_from_csv(filename, wrapper=None):
            if not wrapper:
                wrapper = lambda o: o
            res = list()
            data_file = open(filename, "r")
            data_csv = csv.DictReader(data_file)
            for o in data_csv:
                res.append(wrapper(o))
            data_file.close()
            return res

        def meta_wrapper(o):
            def replace_last(source_string, replace_what, replace_with):
                head, _sep, tail = source_string.rpartition(replace_what)
                return head + replace_with + tail

            res = o
            res['start_date'] = datetime.strptime(replace_last(o['start_date'], ":00", "00"), '%Y-%m-%d %H:%M:%S%z')
            res['end_date'] = datetime.strptime(replace_last(o['end_date'], ":00", "00"), '%Y-%m-%d %H:%M:%S%z')
            res['range'] = int(o['range'])
            return res

        def events_wrapper(o):
            res = o
            tz = pytz.timezone("Europe/Moscow")  # Change in needed
            res['TIMESTAMP'] = dateutil_parser.isoparse(o['TIMESTAMP']).astimezone(tz)
            return res

        def rules_wrapper(o):
            def to_rus(mode):
                rus_modes = {'block_request': "Блокировка запроса",
                             'block_ip': "Блокировка IP-адреса",
                             'block_session': "Блокировка сессии",
                             'sanitize': "Санитизация",
                             'monitoring': "Мониторинг",
                             'count': "Отправка в коррелятор",  # e.g. sent to correlator, but not logged
                             'unknown': "Неизвестный режим",
                             'n/a': "Игнорируется (нет действий)"}
                if mode in rus_modes.keys():
                    return rus_modes[mode]
                else:
                    return mode

            res = o
            res['protector'] = res['protector'].replace("-", "_")
            res['mode'] = to_rus(res["mode"])
            res['enabled'] = True if o["enabled"] == "True" else False
            return res

        def protectors_wrapper(o):
            res = o
            res['nickname'] = res['nickname'].replace("-","_")
            return res

        self.meta = read_from_csv(args.META_FILE, meta_wrapper)[0]
        self.events = read_from_csv(args.EVENTS_FILE, events_wrapper)
        self.protectors = read_from_csv(args.PROTECTORS_FILE, protectors_wrapper)
        self.rules = read_from_csv(args.RULES_FILE, rules_wrapper)
        self.tpl = tpl

    def build_context(self):
        # Populate context with default values
        res = {}
        res['webapp'] = self.meta['webapp']
        res['start_date'] = self.meta['start_date'].strftime("%d.%m.%Y")
        res['end_date'] = self.meta['end_date'].strftime("%d.%m.%Y")
        res['num_of_high_attacks'] = 0
        res['num_of_medium_attacks'] = 0
        res['num_of_low_attacks'] = 0
        res['num_of_info_attacks'] = 0

        # Build DataFrames with events
        events_df = pd.DataFrame(self.events)
        events_low_df = events_df[events_df['EVENT_SEVERITY'] == 'low']
        events_medium_df = events_df[events_df['EVENT_SEVERITY'] == 'medium']
        events_high_df = events_df[events_df['EVENT_SEVERITY'] == 'high']
        events_info_df = events_df[events_df['EVENT_SEVERITY'] == 'info']

        # Attacks by severity
        for e in self.events:
            if e['EVENT_SEVERITY'] == 'high':
                res['num_of_high_attacks'] += 1
            elif e['EVENT_SEVERITY'] == 'medium':
                res['num_of_medium_attacks'] += 1
            elif e['EVENT_SEVERITY'] == 'low':
                res['num_of_low_attacks'] += 1
            elif e['EVENT_SEVERITY'] == 'info':
                res['num_of_info_attacks'] += 1

        # New Attack Dynamics graph (Scatters)
        fig = go.Figure()
        to_timestamp = np.vectorize(lambda x: x.timestamp())
        from_timestamp = np.vectorize(lambda x: datetime.utcfromtimestamp(x).replace(tzinfo=pytz.timezone("Europe/Moscow")))
        events_ts = to_timestamp(events_df['TIMESTAMP'])
        _, events_bins = np.histogram(events_ts, bins=(4*self.meta['range'] if 4*self.meta['range'] > 24 else 24))
        events_bins_dt = from_timestamp(events_bins)
        events_info_ts = to_timestamp(events_info_df['TIMESTAMP']) if len(events_info_df) else []
        info_y, _ = np.histogram(events_info_ts, bins=events_bins)
        fig.add_trace(go.Scatter(x=events_bins_dt, y=info_y, name="info", fill="tozeroy", line=dict(color=SEVERITYTHEME['INFO'], shape="spline", smoothing=0.5, width=3)))

        ## Low Severity Trace
        events_low_ts = to_timestamp(events_low_df['TIMESTAMP']) if len(events_low_df) else []
        low_y, _ = np.histogram(events_low_ts, bins=events_bins)
        fig.add_trace(go.Scatter(x=events_bins_dt, y=low_y, name="low", fill="tozeroy", line=dict(color=SEVERITYTHEME['LOW'], shape="spline", smoothing=0.5, width=3)))

        ## Medium Severity Trace
        events_medium_ts = to_timestamp(events_medium_df['TIMESTAMP']) if len(events_medium_df) else []
        medium_y, _ = np.histogram(events_medium_ts, bins=events_bins)
        fig.add_trace(go.Scatter(x=events_bins_dt, y=medium_y, name="medium", fill="tozeroy", line=dict(color=SEVERITYTHEME['MEDIUM'], shape="spline", smoothing=0.5, width=3)))

        ## High Severity Trace
        events_high_ts = to_timestamp(events_high_df['TIMESTAMP']) if len(events_high_df) else []
        high_y, _ = np.histogram(events_high_ts, bins=events_bins)
        fig.add_trace(go.Scatter(x=events_bins_dt, y=high_y, name="high", fill="tozeroy", line=dict(color=SEVERITYTHEME['HIGH'], shape="spline", smoothing=0.5, width=3)))

        fig.update_layout(template="simple_white",
                          font={"family": "Arial", "size": 18},
                          xaxis={"title": "", 'tickfont': {"family": "Tahoma", "size": 14}},
                          yaxis={"title": "", 'tickfont': {"family": "Tahoma", "size": 14}},
                          autosize=False,
                          width=1200, height=600, margin=dict(l=0, r=0, t=0, b=0))
        fig.write_image('attack_dynamics_img.png')
        res['attack_dynamics_img'] = InlineImage(self.tpl, 'attack_dynamics_img.png', width=Mm(165))

        # TOP 10 Attacks by Type (Bar Histogram)

        ## Strips array-likes to first n elements.
        ## Others will be summarized and added to "Others"
        ## x: x-axis values
        ## y: y-axis values
        ## c: colors
        def strip_to(n, x, y, c):
            if n >= len(x):
                return x,y,c
            res_x = x.tolist()[:n]
            res_y = y.tolist()[:n]
            res_c = c[:n]
            res_x.append("Others")
            res_y.append(sum(y.tolist()[n:]))
            res_c.append("INFO")
            return res_x,res_y,res_c

        severities = {a[0]: a[1] for a in events_df[['EVENT_ID', 'EVENT_SEVERITY']].drop_duplicates().values.tolist()}
        unique, counts = np.unique(events_df['EVENT_ID'], return_counts=True)
        counts_sort_ind = np.argsort(-counts)
        unique = unique[counts_sort_ind]
        counts = counts[counts_sort_ind]
        colors = [severities[e].upper() for e in unique]
        unique, counts, colors = strip_to(10, unique, counts, colors)
        fig = px.bar(x=unique, y=counts, text=counts, color=colors, color_discrete_sequence=SEVERITYTHEME.keys(), color_discrete_map=SEVERITYTHEME)
        fig.update_layout(template="simple_white",
                          font={"family": "Arial", "size": 18},
                          xaxis={"title": "", 'categoryorder': 'array', 'categoryarray': unique, 'tickfont': {"family": "Tahoma", "size": 12}},
                          yaxis_visible=False,
                          showlegend=False,
                          width=1200, height=600, margin=dict(l=0, r=0, t=0, b=0))
        fig.write_image('attacks_by_type_img.png')
        res['attacks_by_type_img'] = InlineImage(self.tpl, 'attacks_by_type_img.png', width=Mm(165))

        # TOP 10 of Attackers IP (Pie Chart)
        client_ips = events_df['CLIENT_IP'].value_counts()[0:10].to_frame("num_of_events")
        fig = px.pie(client_ips, values="num_of_events", names=client_ips.index, hole=0.3)
        fig.update_traces(textinfo='label+percent')
        fig.update_layout(template="simple_white",
                          font={"family": "Tahoma", "size": 16},
                          autosize=False,
                          showlegend=False,
                          width=600, height=600, margin=dict(l=0, r=0, t=0, b=0))
        fig.write_image('top_10_of_attackers_ip_img.png')
        res['top_10_of_attackers_ip_img'] = InlineImage(self.tpl, 'top_10_of_attackers_ip_img.png', width=Mm(80))

        # TOP 10 of attackers IP (table)
        client_ips = events_df['CLIENT_IP'].value_counts()[0:10].to_dict()
        top_10_of_attackers_ip_tbl = [{"ip": ip, "num_of_events": client_ips[ip]} for ip in client_ips.keys()]
        res["top_10_of_attackers_ip_tbl"] = top_10_of_attackers_ip_tbl

        # TOP 10 of Countries (Pie Chart)
        client_cn = events_df[events_df['CLIENT_COUNTRY_NAME'] != '']['CLIENT_COUNTRY_NAME'].value_counts()[0:10].to_frame("num_of_events")
        fig = px.pie(client_cn, values="num_of_events", names=client_cn.index, hole=0.3)
        fig.update_traces(textinfo='label+percent')
        fig.update_layout(template="simple_white",
                          font={"family": "Tahoma", "size": 16},
                          autosize=False,
                          showlegend=False,
                          width=600, height=600, margin=dict(l=0, r=0, t=0, b=0))
        fig.write_image('top_10_of_attackers_cn_img.png')
        res['top_10_of_attackers_cn_img'] = InlineImage(self.tpl, 'top_10_of_attackers_cn_img.png', width=Mm(80))

        # TOP 10 of Countries (table)
        client_cn = events_df[events_df['CLIENT_COUNTRY_NAME'] != '']['CLIENT_COUNTRY_NAME'].value_counts()[0:10].to_dict()
        top_10_of_attackers_cn_tbl = [{"cn": cn, "num_of_events": client_cn[cn]} for cn in client_cn.keys()]
        res["top_10_of_attackers_cn_tbl"] = top_10_of_attackers_cn_tbl

        # TOP 10 of Attackers User Agents (Pie Chart)
        client_ua = events_df[events_df['CLIENT_BROWSER'] != '']['CLIENT_BROWSER'].value_counts()[
                    0:10].to_frame("num_of_events")
        fig = px.pie(client_ua, values="num_of_events", names=client_ua.index, hole=0.3)
        fig.update_traces(textinfo='label+percent')
        fig.update_layout(template="simple_white",
                          font={"family": "Tahoma", "size": 16},
                          autosize=False,
                          showlegend=False,
                          width=600, height=600, margin=dict(l=0, r=0, t=0, b=0))
        fig.write_image('top_10_of_attackers_ua_img.png')
        res['top_10_of_attackers_ua_img'] = InlineImage(self.tpl, 'top_10_of_attackers_ua_img.png', width=Mm(80))

        # TOP 10 of Browsers (table)
        client_ua = events_df[events_df['CLIENT_BROWSER'] != '']['CLIENT_BROWSER'].value_counts()[0:10].to_dict()
        top_10_of_attackers_ua_tbl = [{"ua": ua, "num_of_events": client_ua[ua]} for ua in client_ua.keys()]
        res["top_10_of_attackers_ua_tbl"] = top_10_of_attackers_ua_tbl

        # Protectors and Rules
        for p in self.protectors:
            res[p["nickname"]+"_enabled"] = (True if p["enabled"] == "True" else False)
            if res[p["nickname"]+"_enabled"]:
                res[p["nickname"]+"_rules"] = list()
                for r in self.rules:
                    if r["protector"] == p["nickname"]:
                        if r["enabled"]:
                            res[p["nickname"] + "_rules"].append(r)

        return res

    def build_ua_stat(self):
        # Build DataFrames with events
        events_df = pd.DataFrame(self.events)
        ua_by_event = events_df.groupby(['EVENT_ID', 'CLIENT_USERAGENT']).size().reset_index().rename(
            columns={0: 'count'}).T.to_dict().values()
        return list(ua_by_event)


class Report:
    def __init__(self, args):
        self.template_filename = args.TEMPLATE_FILE
        self.template = DocxTemplate(args.TEMPLATE_FILE)
        self.report = args.REPORT_FILE
        self.ua_csv = args.UA_CSV

    def build(self, dataset):
        print("[~] Starting to build report based on {}".format(self.template_filename))
        self.template.render(dataset.build_context())
        self.template.save(self.report)
        print("[+] Report saved to {}".format(self.report))
        if self.ua_csv:
            self.store_as_csv(dataset.build_ua_stat(), self.ua_csv)
            print("[+] Additional UA stats saved to {}".format(self.ua_csv))

    def store_as_csv(self, list_of_dicts, filename):
        data_file = open(filename, "w")
        if list_of_dicts:
            data_csv = csv.writer(data_file, delimiter=';')
            data_csv.writerow(list_of_dicts[0].keys())
            for o in list_of_dicts:
                row = [s.encode('utf-8') if type(s) == bytes else s for s in o.values()]
                data_csv.writerow(row)
        data_file.close()


class Run:
    def __init__(self, args):
        self.report = Report(args)
        self.dataset = Dataset(self.report.template, args)

    def go(self):
        self.report.build(self.dataset)

def parse_cli_args(test_data=""):
    parser = argparse.ArgumentParser(description='Build report with exported data from PT AF')
    parser.add_argument('-t', '--template',
                        action='store',
                        dest='TEMPLATE_FILE',
                        default=DEFAULT_TEMPLATE_FILE,
                        required=False,
                        help='template file name, {} by default'.format(DEFAULT_TEMPLATE_FILE))
    parser.add_argument('-o', '--output',
                        action='store',
                        dest='REPORT_FILE',
                        default=DEFAULT_REPORT_FILE,
                        required=False,
                        help='report file name, {} by default'.format(DEFAULT_REPORT_FILE))
    parser.add_argument('-m', '--meta',
                        action='store',
                        dest='META_FILE',
                        default=DEFAULT_META_FILE,
                        required=False,
                        help='meta file name, {} by default'.format(DEFAULT_META_FILE))
    parser.add_argument('-r', '--rules',
                        action='store',
                        dest='RULES_FILE',
                        default=DEFAULT_RULES_FILE,
                        required=False,
                        help='rules file name, {} by default'.format(DEFAULT_RULES_FILE))
    parser.add_argument('-p', '--protectors',
                        action='store',
                        dest='PROTECTORS_FILE',
                        default=DEFAULT_PROTECTORS_FILE,
                        required=False,
                        help='protectors file name, {} by default'.format(DEFAULT_PROTECTORS_FILE))
    parser.add_argument('-e', '--events',
                        action='store',
                        dest='EVENTS_FILE',
                        default=DEFAULT_EVENTS_FILE,
                        required=False,
                        help='events file name, {} by default'.format(DEFAULT_EVENTS_FILE))
    parser.add_argument('--ua-csv-file',
                        action='store',
                        dest='UA_CSV',
                        default='',
                        required=False,
                        help='Filename to store UA stats (optional)')

    if test_data:
        args = parser.parse_args(test_data)
    else:
        args = parser.parse_args()

    return args

if __name__ == "__main__":
    r = Run(parse_cli_args())

    # Build a report
    r.go()


