package com.example.myapplication;

import android.util.Log;

import com.bulinbulin.security.KeyPairInfo;
import com.bulinbulin.security.SecurityUtil;

public class TestAll {

    public void test(){

        //*********************生成sm2公私钥*************************
        KeyPairInfo keyPairInfo = new SecurityUtil().createKeyPair();

        Log.w("pubk->",""+keyPairInfo.getPubk());
        Log.w("prik->",""+keyPairInfo.getPrik());

        String pubk = keyPairInfo.getPubk();

        String prik = keyPairInfo.getPrik();

        //*********************sm2公钥加密*************************
        String text = "1234567890";

        long time = System.currentTimeMillis();

        byte[] encText =  new SecurityUtil().sm2Encrypt(text,new SecurityUtil().hexDecode(pubk));

        TimeUtil.timeLog("sm2 encrypt time -->",time);

        Log.w("text-size->",""+encText.length);

        Log.w("test_sm2_encrypt->",new String(encText));

        //*********************sm2私钥解密*************************
        long time1 = System.currentTimeMillis();

        byte[] data =  new SecurityUtil().sm2Decrypt(new String(encText),new SecurityUtil().hexDecode(prik));

        TimeUtil.timeLog("sm2 decrypt time -->",time1);

        Log.w("test_sm2_decrypt->",new String(data));


        //*********************sm3加密*************************
        long time2 = System.currentTimeMillis();

        byte[] sm3Test = "1234567890".getBytes();

        String sm3Data = new SecurityUtil().sm3(sm3Test);

        TimeUtil.timeLog("sm3 encrypt time -->",time2);

        Log.w("test_sm3->",sm3Data);


        //*********************sm4加密*************************
        long time3 = System.currentTimeMillis();

        byte[] sm4Test = "1234567890".getBytes();
        byte[] sm4Key = "1234567812345678".getBytes();

        String sm4EncData = new SecurityUtil().sm4Encrypt(sm4Test,sm4Key);

        TimeUtil.timeLog("sm4 encrypt time -->",time3);

        Log.w("test_sm4_encrypt->",sm4EncData);


        //*********************sm4加密*************************
        long time4 = System.currentTimeMillis();

        byte[] sm4DecData = new SecurityUtil().sm4Decrypt(sm4EncData.getBytes(),sm4Key);

        TimeUtil.timeLog("sm4 decrypt time -->",time4);

        Log.w("test_sm4_decrypt->",new String(sm4DecData));

        //*********************md5加密*************************
        long time5 = System.currentTimeMillis();

        byte[] md5Test = "1234567890".getBytes();

        String md5Data = new SecurityUtil().md5(md5Test);

        TimeUtil.timeLog("md5 encrypt time -->",time5);

        Log.w("test_md5_encrypt->",md5Data);


        //*********************hex加密*************************
        long time6 = System.currentTimeMillis();

        byte[] hexTest = "1234567890".getBytes();

        String hexEncData = new SecurityUtil().hexEncode(hexTest);

        TimeUtil.timeLog("hex encrypt time -->",time6);

        Log.w("test_hex_encrypt->",hexEncData);


        //*********************hex解密*************************
        long time7 = System.currentTimeMillis();

        byte[] hexDecData = new SecurityUtil().hexDecode(hexEncData);

        TimeUtil.timeLog("hex decrypt time -->",time7);

        Log.w("test_hex_decrypt->",new String(hexDecData));


        //*********************base64加密*************************
        long time8 = System.currentTimeMillis();

        byte[] base64Test = "1234567890".getBytes();

        String base64Encode = new SecurityUtil().base64Encode(base64Test);

        TimeUtil.timeLog("base64 encrypt time -->",time8);

        Log.w("test_base64_encrypt->",base64Encode);


        //*********************base64加密*************************
        long time9 = System.currentTimeMillis();

        byte[] base64Decode = new SecurityUtil().base64Decode(base64Encode.getBytes());

        TimeUtil.timeLog("base64 decrypt time -->",time9);

        Log.w("test_base64_encrypt->",new String(base64Decode));

    }



}
