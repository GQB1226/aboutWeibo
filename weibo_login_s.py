#!/usr/bin/env python
# coding=utf-8
__author__="GQB1226"
__date__="20161009"


import requests
import base64
import json
import urllib2
import re
import rsa
import binascii
import urllib
from lxml import etree

def GetServerData():
    url="https://login.sina.com.cn/sso/prelogin.php?entry=weibo&callback=sinaSSOController.preloginCallBack&su=Z3FiMTIyNiU0MHNpbmEuY29t&rsakt=mod&checkpin=1&client=ssologin.js(v1.4.18)&_=1475204885480"
    data=urllib2.urlopen(url).read()
    p=re.compile('\((.*)\)')
    try:
        dic_data=eval(p.search(data).group(1))
        servertime=dic_data['servertime']
        nonce=dic_data['nonce']
        pubkey=dic_data['pubkey']
        rsakv=dic_data['rsakv']
    except:
        print "error"
    return servertime,nonce,pubkey,rsakv


def DecodeUserName(Name):
    #url编码
    _Name=urllib.quote(Name)
    userName=base64.encodestring(_Name)[:-1]
    return userName

def DecodePasswd(passwd,servertime,nonc,pubkey):
    iPubkey=int(pubkey,16)
    key=rsa.PublicKey(iPubkey,65537)#创建公钥
    message=str(servertime)+'\t'+str(nonc)+'\n'+str(passwd)
    password=rsa.encrypt(message,key)
    password=binascii.b2a_hex(password)
    return password


def login(username,passwd):
    #username=base64.b64encode(username.encode('utf-8')).decode('utf-8')
    servertime,nonce,pubkey,raskv=GetServerData()
    un=DecodeUserName(username)
    psw=DecodePasswd(passwd,servertime,nonce,pubkey)
    post_data={
        'entry':'account','gateway':'1',
        'form':'','savestate':'30','useticket':'0',
        'pagerefer':'','vsnf':'1','su':un,'service':'sso',
        'servertime':servertime,'nonce':nonce,'pwencode':'rsa2',
        'rsakv':raskv,'sp':psw,'sr':'1440*900','encoding':'UTF-8',
        'cdult':'30','domain':'sina.com.cn','prelt':"37",
        'returntype':'TEXT'
    }
    url='http://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.15)'
    session=requests.Session()
    res=session.post(url,data=post_data)
    rs=res.content.decode('gbk')
    info=json.loads(rs)
    if info['retcode']=='0':
        print "ok"
        cookies=session.cookies.get_dict()
        cookies=[key+'='+value for key,value in cookies.items()]
        cookies=';'.join(cookies)
        session.headers['cookie']=cookies
    else:
        print "fail for %s"%info["reason"]


if __name__=="__main__":
    login("username","passwd")
