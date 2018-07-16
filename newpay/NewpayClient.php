<?php
/**
 * NewPay php sdk
 * Author: yizhe
 * Date: 2018/6/28
 * Time: 上午11:23
 * @param $privateKey
 * @param $parameterArray
 */
namespace newpay;

use phpseclib\Crypt\RSA;

class NewpayClient {
    function getSign($privateKey, $parameterArray = array()) {
        usort($parameterArray, function ($a, $b) {
            return strcmp($a, $b);
        });
        $data = implode($parameterArray);
        if (empty($data)) {
            echo "数据异常！";
            return null;
        }
        if (empty($privateKey)) {
            echo "私钥异常！";
            return null;
        }
        $p_key_id = openssl_get_privatekey($privateKey);
        if (empty($p_key_id)) {
            echo "私钥异常！";
            return null;
        }
        openssl_sign($data, $signature, $p_key_id, OPENSSL_ALGO_MD5);
        openssl_free_key($p_key_id);
        return base64_encode($signature);
    }

    function genKeyPair() {
        $rsa = new RSA();
        $rsa->setPublicKeyFormat(RSA::PUBLIC_FORMAT_PKCS8);
        $rsa->setPrivateKeyFormat(RSA::PRIVATE_FORMAT_PKCS8);
        $key = $rsa->createKey(1024);
        return array(
            "public_key" => $key["publickey"],
            "private_key" => $key["privatekey"]
        );
    }

    function verify($publicKey, $sign, $parameterArray = array()) {
        usort($parameterArray, function ($a, $b) {
            return strcmp($a, $b);
        });
        $data = implode($parameterArray);
        if (empty($data)) {
            echo "数据异常！";
            return false;
        }
        if (empty($publicKey)) {
            echo "公钥异常！";
            return false;
        }
        $rsa = new RSA();
        $rsa->loadKey($publicKey);
        $p_key_id = openssl_get_publickey($rsa);
        if (empty($p_key_id)) {
            echo "公钥异常！";
            return false;
        }
        return (openssl_verify($data, base64_decode($sign), $p_key_id, OPENSSL_ALGO_MD5) == 1) ? true : false;
    }
}
