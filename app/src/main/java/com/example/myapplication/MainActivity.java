package com.example.myapplication;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Toast;

import com.bulinbulin.security.KeyPairInfo;
import com.bulinbulin.security.SecurityUtil;

public class MainActivity extends AppCompatActivity {

    private String TAG = "MainActivity";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        //检测所有加解密算法
        new TestAll().test();

        //国密公私钥生成
        findViewById(R.id.btn_key_pair).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                KeyPairInfo keyPairInfo = new SecurityUtil().createKeyPair();
                Log.w(TAG,"pubk->"+keyPairInfo.getPubk());
                Log.w(TAG,"prik->"+keyPairInfo.getPrik());
                show("pubk->"+keyPairInfo.getPubk()+"\n"+"prik->"+keyPairInfo.getPrik());
            }
        });

        findViewById(R.id.btn_sm2_encrypt).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                String pubk = "0484A60AFF420D9BA6223594C877F1BD2143D25CAB015D746B3DF3246A62847706FB9AD5ADA27A37058CEF91D73C6CD2032302B85E833B6CB9C06C5089BEF950E7";

                String text = "1234567890";

                long time = System.currentTimeMillis();

                byte[] encText =  new SecurityUtil().sm2Encrypt(text,new SecurityUtil().hexDecode(pubk));

                TimeUtil.timeLog("sm2 encrypt time -->",time);

                Log.w("text-size->",""+encText.length);

                Log.w("test_sm2_encrypt->",new String(encText));

                show(new String(encText));

            }
        });

        //sm2解密
        findViewById(R.id.btn_sm2_decrypt).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                String prik = "1543A76B61C474E18FAF6AFF78F1BFB5B0CE80409850DDD1F4CB7F823834EA0B";

                String encText = "0404EBFC718E8D1798620432268E77FEB6415E2EDE0E073C0F4F640ECD2E149A73E858F9D81E5430A57B36DAAB8F950A3C64E6EE6A63094D99283AFF767E124DF0AB5144E5AA88A3FEF8E2605A30BD58FE33BE2C14064DD4D27195D523C29C7C40E8BBB435CB1981700B17";

                long time1 = System.currentTimeMillis();

                byte[] data =  new SecurityUtil().sm2Decrypt(encText,new SecurityUtil().hexDecode(prik));

                TimeUtil.timeLog("sm2 decrypt time -->",time1);

                Log.w("test_sm2_decrypt->",new String(data));

                show(new String(data));
            }
        });

        //sm3加密
        findViewById(R.id.btn_sm3_enc).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                long time2 = System.currentTimeMillis();

                byte[] sm3Test = "1234567890".getBytes();

                String sm3Data = new SecurityUtil().sm3(sm3Test);

                TimeUtil.timeLog("sm3 encrypt time -->",time2);

                Log.w("test_sm3->",sm3Data);

                show(sm3Data);
            }
        });

        //sm4加密
        findViewById(R.id.btn_sm4_enc).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                long time3 = System.currentTimeMillis();
                //需要加密的数据
                byte[] sm4Test = "1234567890".getBytes();
                //秘钥16字节
                byte[] sm4Key = "1234567812345678".getBytes();

                String sm4EncData = new SecurityUtil().sm4Encrypt(sm4Test,sm4Key);

                TimeUtil.timeLog("sm4 encrypt time -->",time3);

                Log.w("test_sm4_encrypt->",sm4EncData);

                show(sm4EncData);
            }
        });

        //sm4解密
        findViewById(R.id.btn_sm4_dec).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                String sm4EncData = "yvwbEf7TG1SqZZkU5BxPwg==";

                //秘钥16字节
                byte[] sm4Key = "1234567812345678".getBytes();

                long time4 = System.currentTimeMillis();

                byte[] sm4DecData = new SecurityUtil().sm4Decrypt(sm4EncData.getBytes(),sm4Key);

                TimeUtil.timeLog("sm4 decrypt time -->",time4);

                Log.w("test_sm4_decrypt->",new String(sm4DecData));

                show(new String(sm4DecData));
            }
        });

        //md5加密
        findViewById(R.id.btn_md5_enc).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                long time5 = System.currentTimeMillis();

                byte[] md5Test = "1234567890".getBytes();

                String md5Data = new SecurityUtil().md5(md5Test);

                TimeUtil.timeLog("md5 encrypt time -->",time5);

                Log.w("test_md5_encrypt->",md5Data);

                show(md5Data);
            }
        });


        //hex加密
        findViewById(R.id.btn_hex_enc).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                long time6 = System.currentTimeMillis();

                byte[] hexTest = "1234567890".getBytes();

                String hexEncData = new SecurityUtil().hexEncode(hexTest);

                TimeUtil.timeLog("hex encrypt time -->",time6);

                Log.w("test_hex_encrypt->",hexEncData);

                show(hexEncData);
            }
        });


        //hex解密
        findViewById(R.id.btn_hex_dec).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                String hexEncData = "31323334353637383930";

                long time7 = System.currentTimeMillis();

                byte[] hexDecData = new SecurityUtil().hexDecode(hexEncData);

                TimeUtil.timeLog("hex decrypt time -->",time7);

                Log.w("test_hex_decrypt->",new String(hexDecData));


                show(new String(hexDecData));
            }
        });

        //base64加密
        findViewById(R.id.btn_base64_enc).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                long time8 = System.currentTimeMillis();

                byte[] base64Test = "1234567890".getBytes();

                String base64Encode = new SecurityUtil().base64Encode(base64Test);

                TimeUtil.timeLog("base64 encrypt time -->",time8);

                Log.w("test_base64_encrypt->",base64Encode);


                show(base64Encode);
            }
        });


        //base64解密
        findViewById(R.id.btn_base64_dec).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                String base64Encode = "MTIzNDU2Nzg5MA==";

                long time9 = System.currentTimeMillis();

                byte[] base64Decode = new SecurityUtil().base64Decode(base64Encode.getBytes());

                TimeUtil.timeLog("base64 decrypt time -->",time9);

                Log.w("test_base64_encrypt->",new String(base64Decode));

                show(new String(base64Decode));
            }
        });



    }

    private void show(String text){
        Toast.makeText(this,"success->"+text,Toast.LENGTH_SHORT).show();
    }


}
