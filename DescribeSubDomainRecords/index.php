<?php
header( 'Content-Type:text/html;charset=utf-8 ');
date_default_timezone_set('UTC');

//隐藏错误提示
error_reporting(0);

/*
 *  AliyunDNS DescribeSubDomainRecords
 *  该文件 用于查询 子域名 获取RecordId 作为DDNS使用
 *
 */


/* 启用Redis 去掉注释

//Redis用于显示请求频率 防止被aliyunAPI黑名单
$redis = new Redis();
$redis->connect('172.17.0.4', 6379);
$redis->auth("aliddns-api");

//获取客户端真实ip地址
function get_real_ip(){
    static $realip;
    if(isset($_SERVER)){
        if(isset($_SERVER['HTTP_X_FORWARDED_FOR'])){
            $realip=$_SERVER['HTTP_X_FORWARDED_FOR'];
        }else if(isset($_SERVER['HTTP_CLIENT_IP'])){
            $realip=$_SERVER['HTTP_CLIENT_IP'];
        }else{
            $realip=$_SERVER['REMOTE_ADDR'];
        }
    }else{
        if(getenv('HTTP_X_FORWARDED_FOR')){
            $realip=getenv('HTTP_X_FORWARDED_FOR');
        }else if(getenv('HTTP_CLIENT_IP')){
            $realip=getenv('HTTP_CLIENT_IP');
        }else{
            $realip=getenv('REMOTE_ADDR');
        }
    }
    return $realip;
}

$key=get_real_ip();
//限制次数为6 冗余2 也就是10秒一次
$limit = 8;
$check = $redis->exists($key);
if($check){
    $redis->incr($key);
    $count = $redis->get($key);
    if($count > 8){
        exit('请求太频繁，请稍后再试！');
    }
}else{
    $redis->incr($key);
    //限制时间为60秒
    $redis->expire($key,60);
}
$count = $redis->get($key);

*/
//php 正则只保留 汉字 字母 数字 防止XSS
function match_safe($chars,$encoding='utf8')
{
    $pattern =($encoding=='utf8')?'/[\x{4e00}-\x{9fa5}a-zA-Z0-9.@]/u':'/[\x80-\xFF]/';
    preg_match_all($pattern,$chars,$result);
    $temp =join('',$result[0]);
    return $temp;
}

//接收请求GET/POST
$AccessKeyId      = match_safe($_REQUEST['keyid']);     //阿里云颁发给用户的访问服务所用的密钥ID
$AccessKeySecret  = match_safe($_REQUEST['keysecret']); //阿里云颁发给用户的访问服务所用的密钥IDKey
$SubDomain        = match_safe($_REQUEST['subdomain']); //DescribeSubDomainRecords所需要的域名参数


//判断参数
//判断参数
if ($AccessKeyId == null){
    echo "keyid为空，请注意检查哦~";
    exit();
}
if ($AccessKeySecret == null){
    echo "keysecret为空，请注意检查哦~";
    exit();
}
if ($SubDomain == null){
    echo "subdomain为空，请注意检查哦~";
    exit();
}



$SignatureNonce = time();
//公共请求参数 https://help.aliyun.com/document_detail/29745.html
$Format = "XML";                            //返回值的类型，支持JSON与XML。默认为XML
$Version = "2015-01-09";                     //API版本号，为日期形式：YYYY-MM-DD，本版本对应为2015-01-09
$SignatureMethod = "HMAC-SHA1";              //签名方式，目前支持HMAC-SHA1
$SignatureVersion = "1.0";                   //签名算法版本，目前版本是1.0
$SignatureNonce = (string)$SignatureNonce;   //唯一随机数，用于防止网络重放攻击 这里使用时间戳 也可使用UUID
$UTCstring = date('Y-m-d\TH:i:s\Z');  //ISO8601UTC 格式为YYYY-MM-DDThh:mm:ssZ
$Action = "DescribeSubDomainRecords";        //DescribeSubDomainRecords 请求动作

//如果是CURL和调试请求则返回 JSON输出
if(strpos($_SERVER['HTTP_USER_AGENT'],'curl') !== false){
    $Format = "JSON";
}
 

//签名前的请求URL
$url_value = array(
        "Format"=>$Format,
        "AccessKeyId"=>$AccessKeyId,
        "Action"=>$Action,
        "SignatureMethod"=>$SignatureMethod,
        "SubDomain"=>$SubDomain,
        "SignatureNonce"=>$SignatureNonce,
        "SignatureVersion"=>$SignatureVersion,
        "Version"=>$Version,
        "Timestamp"=>$UTCstring
);
//根据关联数组的键，对数组进行升序排列
ksort($url_value);

//数组转URL参数
$paramurl = http_build_query($url_value , '' , '&');


//URL参数 URL编码化
$paramurl = rawurlencode($paramurl);
$paramurl = "GET&%2F&".$paramurl;



//HMAC-SHA1 并按照Base64编码规则把上面的HMAC值编码成字符串  开启raw输出结果转base64
$signKey = $AccessKeySecret."&";
$Signature = hash_hmac("sha1", $paramurl, $signKey, true);
$Signature = base64_encode($Signature);





/*
* 拼接最后URL 并发起请求
*/
$Alidnsurl = "https://alidns.aliyuncs.com/";

//拼接最终请求URL
$url_value_out = array(
    "Action"=>$Action,
    "SubDomain"=>$SubDomain,
    "Format"=>$Format,
    "AccessKeyId"=>$AccessKeyId,
    "SignatureMethod"=>$SignatureMethod,
    "SignatureNonce"=>$SignatureNonce,
    "SignatureVersion"=>$SignatureVersion,
    "Version"=>$Version,
    "Signature"=>$Signature,
    "Timestamp"=>$UTCstring
);
//数组转URL参数
$url_out = $Alidnsurl."?".http_build_query($url_value_out , '' , '&');




echo curl_get($url_out);

function curl_get($url){
    header( 'Content-Type:text/xml;charset=utf-8 ');
    $curl = curl_init();

    curl_setopt_array($curl, array(
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_ENCODING => "",
        CURLOPT_MAXREDIRS => 10,
        CURLOPT_TIMEOUT => 0,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
        CURLOPT_CUSTOMREQUEST => "GET",
    ));

    $response = curl_exec($curl);

    curl_close($curl);

    return $response.PHP_EOL;
 
}
 

