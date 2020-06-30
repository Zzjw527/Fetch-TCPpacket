import tkinter
# 导入消息对话框子模块
import tkinter.messagebox
from tkinter.messagebox import *
from tkinter import *
from function import *
import threading
import os
import re

global condition
global clicktime
clicktime = 0
global cun
cun = []
global sen
sen = 1

def start():
    def get_current_time1():
        current_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
        return current_time


    def get_current_time2():
        current_time = time.strftime('%H:%M:%S', time.localtime(time.time()))
        return current_time


    def startcounttcp():
        global clicktime
        global cun
        global condition
        global amount
        global sen
        lw = isNetChainOK()
        if lw:
            clicktime += 1
            if clicktime == 1:
                warnlabel.set('开始统计中')
                condition = 1
                amount = 0
                while (1):

                    strimfomation = ''
                    if condition == 1:
                        ms = start_count()
                        gtime1 = get_current_time1()
                        gtime2 = get_current_time2()
                        strimfomation = '**********抓包成功**********\n' + 'TCP包解析如下：\n' + '时间' + gtime1 + '\n'
                        for i in ms:
                            strimfomation += i
                            strimfomation += '\n'
                        cun.append(strimfomation)

                        strimfomation += '\n\n\n'
                        text.insert(END, strimfomation)
                        amount += 1
                        stramount = '抓包日志： 已抓取' + str(amount) + '个tcp包'
                        strlabel.set(stramount)
                        ag1 = re.search(r'.*源ip地址： (.*)/*.*', strimfomation, re.M | re.I)
                        ag2 = re.search(r'.*目的ip地址： (.*)/*.*', strimfomation, re.M | re.I)
                        ag3 = re.search(r'.*数据包长度： (.*)/*.*', strimfomation, re.M | re.I)
                        lb.insert(END, ' 序号：' + str(sen) + '    发送/接收' + ag1.group(1) + ' -> ' + ag2.group(
                            1) + '     长度：' + ag3.group(1) + '    时间' + gtime2)
                        sen += 1
                    else:
                        break
            else:
                warnlabel.set('程序运行中，请勿重复点击开始按钮')
        else:
            result = tkinter.messagebox.showerror(title='出错了！', message='内容：连接网络失败，请重新联网')


    def stopcounttcp():
        global condition
        global clicktime
        condition = 0
        clicktime = 0
        warnlabel.set('统计已停止')


    def delete():
        global condition
        condition = 0
        global clicktime
        clicktime = 0
        global sen
        sen = 1
        global cun
        cun = []
        text.delete(1.0, END)
        warnlabel.set('正在清空中请稍后')
        text.delete(1.0, END)
        time.sleep(3)
        text.delete(1.0, END)
        amount = 0
        strlabel.set('抓包日志： 清空完毕')
        warnlabel.set('点击开始统计可以重新进行统计')
        lb.delete(0, END)
        # temp1 = lb.get(lb.curselection())
        # print(temp1)


    def openimf(event):
        temp1 = lb.get(lb.curselection())
        xu = re.search(r' 序号：(.*)    发送.*', temp1, re.M | re.I)
        aq1 = re.search(r'.*时间(.*)/*.*', cun[int(xu.group(1)) - 1], re.M | re.I)
        aq2 = re.search(r'.*源ip地址： (.*)/*.*', cun[int(xu.group(1)) - 1], re.M | re.I)
        aq3 = re.search(r'.*目的ip地址： (.*)/*.*', cun[int(xu.group(1)) - 1], re.M | re.I)
        aq4 = re.search(r'.*源MAC地址： (.*)/*.*', cun[int(xu.group(1)) - 1], re.M | re.I)
        aq5 = re.search(r'.*目的MAC地址： (.*)/*.*', cun[int(xu.group(1)) - 1], re.M | re.I)
        aq6 = re.search(r'.*数据包长度： (.*)/*.*', cun[int(xu.group(1)) - 1], re.M | re.I)
        aq7 = re.search(r'.*发送端口号： (.*)/*.*', cun[int(xu.group(1)) - 1], re.M | re.I)
        aq8 = re.search(r'.*接收端口号： (.*)/*.*', cun[int(xu.group(1)) - 1], re.M | re.I)
        top = Tk()
        top.geometry("400x380+200+150")
        top.title("TCP包具体解析")
        frmtop1 = Frame(top)
        frmtop1.pack(fill=X, padx=10, pady=3)
        frmtop2 = Frame(top)
        frmtop2.pack(fill=X, padx=10, pady=3)
        top = Frame(top)
        top.pack(fill=X, padx=10, pady=10)
        toptap = Label(frmtop1, text='TCP包解析' + '', font=("微软雅黑", 20), fg='blue')
        toptap.pack(fill=X, padx=10, pady=3)
        toplabel1 = Label(frmtop2, text='源ip地址：' + str(aq2.group(1)) + '', anchor=NW, font=("微软雅黑", 12))
        toplabel1.pack(fill=X, padx=10, pady=2)
        toplabel2 = Label(frmtop2, text='目的ip地址：' + str(aq3.group(1)), anchor=NW, font=("微软雅黑", 12))
        toplabel2.pack(fill=X, padx=10, pady=2)
        toplabel3 = Label(frmtop2, text='源MAC地址：' + str(aq4.group(1)), anchor=NW, font=("微软雅黑", 12))
        toplabel3.pack(fill=X, padx=10, pady=2)
        toplabel4 = Label(frmtop2, text='目的MAC地址：' + str(aq5.group(1)), anchor=NW, font=("微软雅黑", 12))
        toplabel4.pack(fill=X, padx=10, pady=2)
        toplabel5 = Label(frmtop2, text='数据包长度：' + str(aq6.group(1)), anchor=NW, font=("微软雅黑", 12))
        toplabel5.pack(fill=X, padx=10, pady=2)
        toplabel6 = Label(frmtop2, text='发送端口号：' + str(aq7.group(1)), anchor=NW, font=("微软雅黑", 12))
        toplabel6.pack(fill=X, padx=10, pady=2)
        toplabel7 = Label(frmtop2, text='接收端口号：' + str(aq8.group(1)), anchor=NW, font=("微软雅黑", 12))
        toplabel7.pack(fill=X, padx=10, pady=2)
        toplabel8 = Label(frmtop2, text='传输层协议类型： 6(TCP)', anchor=NW, font=("微软雅黑", 12))
        toplabel8.pack(fill=X, padx=10, pady=2)
        toplabel9 = Label(frmtop2, text='抓包时间：' + str(aq1.group(1)), anchor=NW, font=("微软雅黑", 12))
        toplabel9.pack(fill=X, padx=10, pady=2)


    def thread_it(func, *args):
        '''将函数打包进线程'''
        t = threading.Thread(target=func, args=args)
        t.setDaemon(True)
        t.start()


    master = Tk()
    master.geometry("900x520+100+100")
    master.title("TCP流量统计系统")

    frmb = Frame(master)
    frmb.grid(row=0, column=0)
    frmbutton = Frame(master)
    frmbutton.grid(row=1, column=0)
    frmn = Frame(master)
    frmn.grid(row=0, column=1)
    frmrz = Frame(master)
    frmrz.grid(row=1, column=1)
    frmr = Frame(master)
    frmr.grid(row=2, column=1)
    frmc = Frame(master)
    frmc.grid(row=2, column=0)

    strlabel = StringVar()
    warnlabel = StringVar()
    sblabel = Label(frmc, text='双击可显示具体信息', justify=LEFT, font=("微软雅黑", 12), fg='red')
    sblabel.grid(row=0, column=1)
    blabel = Label(frmb, text='TCP流量统计系统', justify=LEFT, font=("微软雅黑", 20), fg='blue')
    blabel.grid(row=0, column=0)
    nlabel = Label(frmn, relief=RIDGE, text='班级：信息安全2班    姓名：张家维    学号：3118005433 ')
    nlabel.grid(row=0, column=1)
    wlabel = Label(frmrz, textvariable=strlabel)
    wlabel.grid(row=0, column=4)
    tlabel = Label(frmrz, textvariable=warnlabel)
    tlabel.grid(row=1, column=4)
    warnlabel.set('')
    strlabel.set('抓包日志： 已抓取0个tcp包')

    thebutton1 = Button(frmbutton, text="开始统计", bg="lightblue", width=20, command=lambda: thread_it(startcounttcp))
    thebutton1.grid(row=0, column=1)
    thebutton2 = Button(frmbutton, text="停止统计", bg="lightblue", width=20, command=lambda: thread_it(stopcounttcp))
    thebutton2.grid(row=0, column=2, pady=5)
    thebutton3 = Button(frmbutton, text="清空", bg="lightblue", width=20, command=lambda: thread_it(delete))
    thebutton3.grid(row=0, column=3, pady=5)

    sb = Scrollbar(frmc)
    sb.grid(row=1, column=2, sticky='ns')
    lb = Listbox(frmc, width=70, height=20, selectmode=SINGLE, yscrollcommand=sb.set)
    lb.grid(row=1, column=1)
    sb.config(command=lb.yview)
    lb.bind('<Double-Button-1>', openimf)

    text = Text(frmr, width=50, height=30)
    text.grid(row=2, column=4)

    master.mainloop()



