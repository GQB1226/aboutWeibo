#!coding=utf-8
#weibo login
__author__="gqb1226"
__date__="20160929"

import urllib
import urllib2
import base64
import re
import rsa
import binascii
import cookielib


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

def cookies():
    ck=cookielib.CookieJar()
    cs=urllib2.HTTPCookieProcessor(ck)
    opener=urllib2.build_opener(cs,urllib2.HTTPHandler)
    urllib2.install_opener(opener)

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


def login(username,passwd):
    cookies();
    url='http://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.18)'
    headers={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0'}
    servertime,nonce,pubkey,raskv=GetServerData()
    un=DecodeUserName(username)
    psw=DecodePasswd(passwd,servertime,nonce,pubkey)

    post_data={
        'entry':'weibo','gateway':'1',
        'form':'','savestate':'7','useticket':'1',
        'pagerefer':'','vsbf':'1','su':un,'service':'miniblog',
        'servertime':servertime,'nonce':nonce,'pwencode':'rsa2',
        'rsakv':raskv,'sp':psw,'sr':'1440*900','encoding':'UTF-8',
        'prelt':'80','url':'http://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack',
        'returntype':'META'
    }

    data=urllib.urlencode(post_data)
    request=urllib2.Request(url,data,headers)
    res=urllib2.urlopen(request)
    text=res.read()
    p=re.compile("location\.replace\(\'(.*)\'\)")
    real_url=p.search(text).group(1)
    d=urllib2.urlopen(real_url)
    print d.read()

if  __name__=="__main__":
    login(username,passwd)

