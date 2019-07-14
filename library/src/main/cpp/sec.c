//
// Created by lulu on 19-3-12.
//
#include <openssl/ossl_typ.h>
#include <openssl/evp.h>
#include "sec.h"
#include "sm3hash.h"
#include "log.h"
#include "test_sm2_encrypt_and_decrypt.h"
#include "sm2_encrypt_and_decrypt.h"
#include "hex.h"
#include "sm2_create_key_pair.h"
#include "md5.h"
#include "sm4.h"
#include "base64.h"
#include <stddef.h>
#include <memory.h>


JNIEXPORT jobject JNICALL
Java_com_bulinbulin_security_SecurityUtil_createKeyPair(JNIEnv *env, jobject instance){

    int error_code;
    SM2_KEY_PAIR key_pair;
    if ( error_code = sm2_create_key_pair(&key_pair) )
    {
        LOGD("test Create SM2 key pair failed!\n");
        return (-1);
    }
    LOGD("test Create SM2 key pair succeeded!\n");

    //获取对象方法
    jclass cls = (*env)->FindClass(env, "com/bulinbulin/security/KeyPairInfo");

    //获取构造方法，I(整形) Ljava/lang/String;(字符串) [B(byte[]) 括号里面表示初始化方法的参数
    jmethodID id = (*env)->GetMethodID(env, cls, "<init>", "()V");

    //创建一个jobject对象.
    jobject paramOut = (*env)->NewObject(env,cls, id);

    //获取类中每一个变量的定义
    //pubk
    jfieldID pubk = (*env)->GetFieldID(env,cls, "pubk", "Ljava/lang/String;");

    //prik
    jfieldID prik = (*env)->GetFieldID(env,cls, "prik", "Ljava/lang/String;");

    //将公钥与私钥转换成十六进制
    unsigned char *pubkHex = malloc(130+1);
    memset(pubkHex,0x00,131);
    hexEncode(key_pair.pub_key,65,pubkHex);

    unsigned char *prikHex = malloc(64+1);
    memset(prikHex,0x00,65);
    hexEncode(key_pair.pri_key,32,prikHex);
    //赋值对象进行返回
    (*env)->SetObjectField(env, paramOut, pubk, (*env)->NewStringUTF(env,pubkHex));
    (*env)->SetObjectField(env, paramOut, prik, (*env)->NewStringUTF(env,prikHex));

    return paramOut;
}



JNIEXPORT jbyteArray JNICALL
Java_com_bulinbulin_security_SecurityUtil_sm2Encrypt(JNIEnv *env, jobject instance, jstring input_,jbyteArray key_) {

    const char *input = (*env)->GetStringUTFChars(env,input_, 0);

    int input_len = (*env)->GetStringLength(env,input_);

    const char *key  = (*env)->GetByteArrayElements(env,key_, 0);

    int key_len = (*env)->GetArrayLength(env,key_);

    LOGD("input_len->%d",input_len);

    LOGD("key_len->%d",key_len);

    int error_code;

    unsigned char *output = malloc(input_len+97+1);

    int encryptLen = input_len+97;

    memset(output,0x00,encryptLen+1);

    if ( error_code = sm2_encrypt_data(input,input_len,key,output) )
    {
        LOGD("Create SM2 ciphertext failed!%d\n",error_code);
        goto clean_up;
    }

    //加密完成后C1C2C3,进行hex编码
    unsigned char *hex_sha=malloc(encryptLen*2+1);

    memset(hex_sha,0x00,encryptLen*2+1);

    hexEncode(output,encryptLen,hex_sha);

    LOGD("hexStrss->%d",strlen(hex_sha));

    jbyteArray retByte = (*env)->NewByteArray(env,encryptLen*2);
    if (NULL != retByte) {
        (*env)->SetByteArrayRegion(env,retByte, 0, encryptLen*2, (jbyte *)hex_sha);
    }

clean_up:
    if (input)
    {
        free(input);
    }

    if(key){
        free(key);
    }

    if(output){
        free(output);
    }

    if(hex_sha){
        free(hex_sha);
    }

    return retByte;
}


JNIEXPORT jbyteArray JNICALL
Java_com_bulinbulin_security_SecurityUtil_sm2Decrypt(JNIEnv *env, jobject instance, jstring input_,
                                                   jbyteArray key_) {
    const char *input = (*env)->GetStringUTFChars(env,input_, 0);

    int input_len = (*env)->GetStringLength(env,input_);

    const char *key  = (*env)->GetByteArrayElements(env,key_, 0);
    int error_code;
    //解密hex
    unsigned char *output = malloc(input_len/2+1);
    memset(output,0x00,input_len/2+1);
    int len = hexDecode(input,output);
    LOGD("len->%d",len);
    //取出C1，C2，C3
    unsigned char c1[65], c3[32];
    unsigned char *c2, *plaintext;;

    int resultLen = len - 65 -32;

    c2 = malloc(resultLen+1);
    memset(c2,0x00,resultLen+1);

    plaintext = malloc(resultLen+1);
    memset(plaintext,0x00,resultLen+1);

    memcpy(c1,output,65);
    memcpy(c2,output+65,resultLen);

    memcpy(c3,output+65+resultLen,32);

    jbyteArray retByte = (*env)->NewByteArray(env,resultLen);

    //解密
    if ( error_code = sm2_decrypt1(c1,c3,c2,resultLen,key,plaintext) )
    {
        free(plaintext);
        free(c2);
        LOGD("Decrypt SM2 ciphertext by using private key defined in standard failed!%d\n",error_code);
        goto clean_up;
    }
    LOGD("plaintext->%s ", plaintext);

    if (NULL != retByte) {
        (*env)->SetByteArrayRegion(env,retByte, 0, resultLen, (jbyte *)plaintext);
    }

clean_up:

    (*env)->ReleaseStringUTFChars(env,input_, input);
    (*env)->ReleaseByteArrayElements(env,key_, key, 0);

    return retByte;
}



JNIEXPORT jstring JNICALL
Java_com_bulinbulin_security_SecurityUtil_sm3(JNIEnv *env, jobject instance,jbyteArray srcjStr){

    jbyte *unicodeDataChar = (*env)->GetByteArrayElements(env,srcjStr, NULL);
    int inputLen = (*env)->GetArrayLength(env,srcjStr);

    char result[65] = {'\0'};
    unsigned char hash_value[64];
    unsigned int hash_len;
    sm3_hash((unsigned char*)unicodeDataChar, inputLen, hash_value, &hash_len);
    for (int i = 0; i < hash_len; i++) {
         sprintf(&result[i*2], "%02x", hash_value[i]);
    }
    LOGD("result=%s",result);
    const char* constc = result;
    //释放资源
    (*env)->ReleaseByteArrayElements(env,srcjStr, unicodeDataChar, 0);
    return  (*env)->NewStringUTF(env,constc);
}


JNIEXPORT jstring JNICALL
Java_com_bulinbulin_security_SecurityUtil_sm4Encrypt(JNIEnv *env, jobject instance, jbyteArray input,
                                                     jbyteArray keyStr) {
    sm4_context ctx;
    jbyte *unicodeKeyChar = (*env)->GetByteArrayElements(env,keyStr,NULL);
    jbyte * unicodeDataChar = (*env)->GetByteArrayElements(env,input, NULL);

    int inputLen = (*env)->GetArrayLength(env,input);

    //获取密钥
    unsigned char user_key[17];
    memset(user_key,0,16);
    memcpy(user_key,unicodeKeyChar,16);
    user_key[16] = '\0';

    int keyLen = strlen((const char *) user_key);

    //获取需要加密的内容
    unsigned char* inputBuf = (unsigned char *) malloc(inputLen+1);
    memcpy(inputBuf,unicodeDataChar,inputLen);
    inputBuf[inputLen] = '\0';
    sm4_setkey_enc(&ctx, user_key);
    //自己想padding一下
    //计算需要的空间
    int p = 16 - inputLen % 16;

    int aLen = inputLen + p;

    unsigned char* result = (unsigned char *) malloc(aLen+1);
    result[aLen] = '\0';
    int  paddingLen = padding((char *) inputBuf,result, SM4_ENCRYPT);
    //
    unsigned  char* output = (unsigned char *) malloc(paddingLen + 1);
    output[paddingLen] = '\0';
    sm4_crypt_cbc(&ctx, SM4_ENCRYPT, paddingLen, user_key, result, output);

    //在进行base64处理
    int nBaseLen = modp_b64_encode_len(paddingLen);

    unsigned char* buf = (unsigned char *) malloc(nBaseLen + 1);

    buf[nBaseLen] = '\0';

    //base64_encode(output, paddingLen, buf);

    int n = EncodeBase64(output,buf,paddingLen);

    //LOGD("buf-SM4Encrypt-base64==%d",n);

    char* output1 = (char *) malloc(n + 1);

    memset(output1,'\0',n + 1);

    memcpy(output1,buf,n);

    (*env)->ReleaseByteArrayElements(env,input, unicodeDataChar, 0);
    (*env)->ReleaseByteArrayElements(env,keyStr, unicodeKeyChar, 0);

    return (*env)->NewStringUTF(env,output1);
}



JNIEXPORT jbyteArray JNICALL
Java_com_bulinbulin_security_SecurityUtil_sm4Decrypt(JNIEnv *env, jobject instance, jbyteArray input,
                                                     jbyteArray keyStr) {
//    jbyte *test = (*env)->GetByteArrayElements(env, test_, NULL);
//
//
//    (*env)->ReleaseByteArrayElements(env, test_, test, 0);
//    const char* constc;
//    jbyteArray retByte = (*env)->NewByteArray(env,11);
//    return retByte;

    //LOGD("buf--SM4Decrypt__进入的sm4解密==%d",1);

    jbyte *unicodeKeyChar = (*env)->GetByteArrayElements(env,keyStr,NULL);
    jbyte *unicodeDataChar = (*env)->GetByteArrayElements(env,input, NULL);

    int inputLen = (*env)->GetArrayLength(env,input);

    //LOGD("buf--SM4Decrypt_GetArrayLength_inputLen==%d",inputLen);

    //int strLen = strlen((const char *) unicodeDataChar);

    //LOGD("buf--SM4Decrypt_strlen_inputLen==%d",strLen);
    //获取解密密钥
    unsigned char user_key[17];
    memset(user_key,0,16);
    memcpy(user_key,unicodeKeyChar,16);
    user_key[16] = '\0';

    //获取需要解密的内容
    unsigned char* inputBuf = (unsigned char *) malloc(inputLen+1);

    memcpy(inputBuf,unicodeDataChar,inputLen);
    inputBuf[inputLen] = '\0';

    int str_size1 =  modp_b64_decode_len(inputLen);

    unsigned char* AfBase64str = (unsigned char *) malloc(str_size1+1);

    int n = DecodeBase64(inputBuf,AfBase64str,inputLen);

    //LOGD("result data: %d bytes \n", n);

    sm4_context ctx;

    //encrypt standard testing vector
    sm4_setkey_dec(&ctx,user_key);

    sm4_crypt_cbc(&ctx, SM4_DECRYPT,n,user_key,AfBase64str,AfBase64str);

    //进行padding

    int num = n - 1;

    //LOGD("计算padding去掉的值--buf==----------------num--------%d",num);

    int p = AfBase64str[num];

    //LOGD("计算padding去掉的值--buf==-----------------p-------%d",p);

    int aLen = n - p;

    if(aLen<=0){
        LOGD("发现解密异常,直接返回原文==--------------------%d",aLen);
        return  input;
    }

    unsigned char* result = (unsigned char *) malloc(aLen + 1);

    memset(result,'\0',aLen+1);

    int lenn =  paddingDecode(AfBase64str,result,n);

    free(AfBase64str);

    jbyteArray retByte = 0;

    retByte = (*env)->NewByteArray(env,lenn);
    if (NULL != retByte)
    {
        (*env)->SetByteArrayRegion(env,retByte, 0, lenn, (jbyte *)result);
    }
    //一定要释放，要不就死定了
    (*env)->ReleaseByteArrayElements(env,input, unicodeDataChar, NULL);
    (*env)->ReleaseByteArrayElements(env,keyStr, unicodeKeyChar, NULL);

    return retByte;
}

JNIEXPORT jstring JNICALL
Java_com_bulinbulin_security_SecurityUtil_md5(JNIEnv *env, jobject instance, jbyteArray data_) {

    jbyte *unicodeDataChar  = (*env)->GetByteArrayElements(env,data_, NULL);

    int inputLen = (*env)->GetArrayLength(env,data_);
    //获取需要解密的内容
    unsigned char* inputBuf = (unsigned char *) malloc(inputLen+1);
    memcpy(inputBuf,unicodeDataChar,inputLen);
    inputBuf[inputLen] = '\0';
    MD5_CTX context = { 0 };
    MD5Init(&context);
    MD5Update(&context, inputBuf, inputLen);
    unsigned char dest[16] = { 0 };
    MD5Final(dest, &context);
    int i = 0;
    char szMd5[32] = { 0 };
    for (i = 0; i < 16; i++)
    {
        sprintf(szMd5, "%s%02x", szMd5, dest[i]);
    }

    (*env)->ReleaseByteArrayElements(env,data_, unicodeDataChar, NULL);

    return  (*env)->NewStringUTF(env,szMd5);
}


JNIEXPORT jstring JNICALL
Java_com_bulinbulin_security_SecurityUtil_hexEncode(JNIEnv *env, jobject instance,jbyteArray data_) {

    jbyte *data = (*env)->GetByteArrayElements(env, data_, NULL);
    int inputLen = (*env)->GetArrayLength(env,data_);
    //开辟控件进行编码
    unsigned char* output = (unsigned char *) malloc(inputLen*2+1);
    memset(output,0x00,inputLen*2+1);
    hexEncode(data,inputLen,output);
    (*env)->ReleaseByteArrayElements(env, data_, data, 0);
    return (*env)->NewStringUTF(env, output);
}

JNIEXPORT jbyteArray JNICALL
Java_com_bulinbulin_security_SecurityUtil_hexDecode(JNIEnv *env, jobject instance, jstring data_) {

    const char *data = (*env)->GetStringUTFChars(env, data_, 0);
    int input_len = (*env)->GetStringLength(env,data_);

    int resultLen = input_len/2;
    //开辟控件进行解码
    unsigned char* output = (unsigned char *) malloc(resultLen + 1);
    memset(output,0x00,resultLen + 1);
    hexDecode(data,output);
    (*env)->ReleaseStringUTFChars(env, data_, data);

    jbyteArray retByte = (*env)->NewByteArray(env,resultLen);
    if (NULL != retByte) {
        (*env)->SetByteArrayRegion(env,retByte, 0, resultLen, (jbyte *)output);
    }
    return retByte;
}


JNIEXPORT jstring JNICALL
Java_com_bulinbulin_security_SecurityUtil_base64Encode(JNIEnv *env, jobject instance,
                                                       jbyteArray data_) {
    jbyte *unicodeDataChar = (*env)->GetByteArrayElements(env,data_, NULL);
    int inputLen = (*env)->GetArrayLength(env,data_);
    //获取需要加密的内容
    unsigned char* inputBuf = (unsigned char *) malloc(inputLen+1);
    memcpy(inputBuf,unicodeDataChar,inputLen);
    inputBuf[inputLen] = '\0';
    //在进行base64处理
    int nBaseLen = modp_b64_encode_len(inputLen);
    unsigned char* buf = (unsigned char *) malloc(nBaseLen + 1);
    buf[nBaseLen] = '\0';

    int n = EncodeBase64(inputBuf,buf,inputLen);

    char* result = (char *) malloc(n + 1);

    memset(result,'\0',n + 1);

    memcpy(result,buf,n);

    (*env)->ReleaseByteArrayElements(env,data_, unicodeDataChar, 0);

    return (*env)->NewStringUTF(env,result);
}

JNIEXPORT jbyteArray JNICALL
Java_com_bulinbulin_security_SecurityUtil_base64Decode(JNIEnv *env, jobject instance,
                                                       jbyteArray data_) {
    jbyte *unicodeDataChar  = (*env)->GetByteArrayElements(env,data_, NULL);
    int inputLen = (*env)->GetArrayLength(env,data_);
    //获取需要解密的内容,将需要解密的内容拷贝到inputBuf中
    unsigned char* inputBuf = (unsigned char *) malloc(inputLen+1);
    memcpy(inputBuf,unicodeDataChar,inputLen);
    inputBuf[inputLen] = '\0';
    //获取解密后的长度
    int str_size1 =  modp_b64_decode_len(inputLen);
    //申请解密后的数组内存空间
    unsigned char* AfBase64str = (unsigned char *) malloc(str_size1+1);
    int n = DecodeBase64(inputBuf,AfBase64str,inputLen);
    jbyteArray retByte = 0;
    retByte = (*env)->NewByteArray(env,n);
    if (NULL != retByte)
    {
        (*env)->SetByteArrayRegion(env,retByte, 0, n, (jbyte *)AfBase64str);
    }
    (*env)->ReleaseByteArrayElements(env,data_, unicodeDataChar, 0);
    return retByte;
}