import logging
import sqlite3
import time
import hmac
import urllib
import hashlib
import base64
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.wait import WebDriverWait
from dingtalkchatbot.chatbot import DingtalkChatbot, FeedLink


def sendDingTalkMsg(text: str):
    """
    使用钉钉群聊天机器人发送消息
    :param text: 消息内容
    :return:
    """
 
    """第一: 发送文本-->
        send_text(self,msg,is_at_all=False,at_mobiles=[],at_dingtalk_ids=[],is_auto_at=True)
            msg: 发送的消息
            is_at_all:是@所有人吗? 默认False,如果是True.会覆盖其它的属性
            at_mobiles:要@的人的列表,填写的是手机号
            at_dingtalk_ids:未知;文档说的是"被@人的dingtalkId（可选）"
            is_auto_at:默认为True.经过测试,False是每个人一条只能@一次,重复的会过滤,否则不然,测试结果与文档不一致
        """
    SignMessage = getSIGN()
    xiaoDing = DingtalkChatbot(SignMessage)  # 初始化机器人
    xiaoDing.send_text(text)
    logging.error('钉钉发送消息:' + text)

    return


# 获取链接,填入urlToken 和 secret
def getSIGN():
    timestamp = str(round(time.time() * 1000))
    urlToken = "https://oapi.dingtalk.com/robot/send?access_token=************************************"
    secret = '************************************"'
    secret_enc = secret.encode('utf-8')
    string_to_sign = '{}\n{}'.format(timestamp, secret)
    string_to_sign_enc = string_to_sign.encode('utf-8')
    hmac_code = hmac.new(secret_enc, string_to_sign_enc, digestmod=hashlib.sha256).digest()
    sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))

    SignMessage = urlToken + "&timestamp=" + timestamp + "&sign=" + sign
    return SignMessage


# 初始化数据库
conn = sqlite3.connect('SecurityMonitor.sqlite')


def insertThreat(data):
    """
    添加威胁到数据库
    :return:
    """
    cur = conn.cursor()  # 创建游标对象
    cur.execute('INSERT INTO threat_table (src_ip, proxy_ip, assets_ip, region, submit_method, attack_types, '
                'hazard_level, attack_time, esid) VALUES(?,?,?,?,?,?,?,?,?)', data)  # execute执行
    conn.commit()  # commit提交
    cur.close()


def selectThreat(data_esid):
    """
    从数据库查询威胁
    :param data_esid: 威胁号
    :return:
    """
    cur = conn.cursor()
    cursor = cur.execute('SELECT threat_table.id, src_ip, proxy_ip, assets_ip, region, submit_method, attack_types, '
                         'hazard_level, attack_time, esid FROM threat_table WHERE esid = ?', data_esid)
    data_all = cursor.fetchall()
    if len(data_all) == 0:
        return None
    # for row in data_all:
    #     # print(row)
    cur.close()
    return data_all


def run():
    options = webdriver.ChromeOptions()
    # options.add_argument("--proxy-server=http://127.0.0.1:1080")
    # options.add_argument('disable-infobars')      # 谷歌浏览器版本在V75以及以下解决办法
    # options.add_argument('headless')              # 谷歌浏览器版本在V75以及以下解决办法
    options.add_experimental_option('useAutomationExtension', False)  # 谷歌浏览器版本在V76以及以上解决办法
    options.add_experimental_option('excludeSwitches', ['enable-automation'])  # 谷歌浏览器版本在V76以及以上解决办法
    browser = webdriver.Chrome(chrome_options=options)
    browser.get("https://*.*.*.*:*/")
    # ####################### 登录
    xpath_str_username = '//*[@id="username"]'
    WebDriverWait(browser, 20000).until(EC.visibility_of_element_located((By.XPATH, xpath_str_username)))
    logging.error('网页加载完毕')
    # 填入用户名
    element = browser.find_element_by_id('username')
    element.send_keys('******')

    # 填入密码
    element = browser.find_element_by_id('password')
    element.send_keys(r'*******')

    # 点击登录按钮
    element = browser.find_element_by_xpath('/html/body/div/div[3]/ul/li[4]/a')
    element.click()

    # ####################### 点击威胁分析-》全局分析
    xpath_str_weixiefenxi = '/html/body/div[3]/div[1]/div/ul/li[3]/a/span[1]'
    WebDriverWait(browser, 20000).until(EC.visibility_of_element_located((By.XPATH, xpath_str_weixiefenxi)))
    element = browser.find_element_by_link_text('威胁分析')
    element.click()
    time.sleep(1)
    element = browser.find_element_by_link_text('全局分析')
    element.click()
    while 1:
        # ####################### 分析威胁
        xpath = '//*[@id="global-analyze-table-title-1"]/tbody'
        WebDriverWait(browser, 20000).until(EC.visibility_of_element_located((By.XPATH, xpath)))
        elements = browser.find_elements_by_xpath('//*[@id="global-analyze-table-title-1"]/tbody/tr')
        # print(elements)
        for element in elements:
            # print(element)
            tds = element.find_elements_by_tag_name('td')
            data_esid = tds[0].find_element_by_tag_name('input').get_attribute('data-esid')
            src_ip = tds[1].text
            assets_ip = tds[2].text
            region = tds[3].text
            submit_method = tds[4].text
            attack_types = tds[5].text
            hazard_level = tds[6].text
            attack_time = tds[9].text

            # print(src_ip, assets_ip, region, submit_method, attack_types, hazard_level, attack_time)

            if selectThreat([data_esid, ]) is None:
                insertThreat(
                    [src_ip, '', assets_ip, region, submit_method, attack_types, hazard_level, attack_time, data_esid])

                text = """
%s
目标地址： %s
攻击IP：%s
攻击手段： %s
攻击方式： %s
""" % (attack_time, assets_ip, src_ip, attack_types, submit_method)
                # print(text)
                sendDingTalkMsg(text)
                print(src_ip, assets_ip, region, submit_method, attack_types, hazard_level, attack_time)
        # //*[@id="username"]

        for i in range(30):
            print('距离刷新还有%d秒。' % (30 - i))
            time.sleep(1)
        browser.refresh()


if __name__ == '__main__':
    logging.basicConfig(format='%(asctime)s - %(pathname)s[line:%(lineno)d] - %(levelname)s: %(message)s',
                        level=logging.ERROR)
    run()
    conn.close()
