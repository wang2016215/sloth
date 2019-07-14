//
// Created by lulu on 19-3-12.
//
#include <jni.h>

JNIEXPORT jobject JNICALL
Java_com_bulinbulin_security_SecurityUtil_createKeyPair(JNIEnv *env, jobject instance);

JNIEXPORT jbyteArray JNICALL
Java_com_bulinbulin_security_SecurityUtil_sm2Encrypt(JNIEnv *env, jobject instance, jstring test_,
        jbyteArray key_);

JNIEXPORT jbyteArray JNICALL
Java_com_bulinbulin_security_SecurityUtil_sm2Decrypt(JNIEnv *env, jobject instance, jstring test_,
        jbyteArray key_);

JNIEXPORT jstring JNICALL
Java_com_bulinbulin_security_SecurityUtil_sm3(JNIEnv *env, jobject instance,jstring srcjStr);


JNIEXPORT jstring JNICALL
Java_com_bulinbulin_security_SecurityUtil_sm4Encrypt(JNIEnv *env, jobject instance, jbyteArray test_,
                                                     jbyteArray key);

JNIEXPORT jbyteArray JNICALL
Java_com_bulinbulin_security_SecurityUtil_sm4Decrypt(JNIEnv *env, jobject instance, jbyteArray test_,
                                                     jbyteArray key);


JNIEXPORT jstring JNICALL
Java_com_bulinbulin_security_SecurityUtil_md5(JNIEnv *env, jobject instance, jbyteArray data_);

JNIEXPORT jstring JNICALL
Java_com_bulinbulin_security_SecurityUtil_hexEncode(JNIEnv *env, jobject instance,jbyteArray data_);

JNIEXPORT jbyteArray JNICALL
Java_com_bulinbulin_security_SecurityUtil_hexDecode(JNIEnv *env, jobject instance, jstring data_);

JNIEXPORT jstring JNICALL
Java_com_bulinbulin_security_SecurityUtil_base64Encode(JNIEnv *env, jobject instance,
                                                       jbyteArray data_);

JNIEXPORT jbyteArray JNICALL
Java_com_bulinbulin_security_SecurityUtil_base64Decode(JNIEnv *env, jobject instance,
                                                       jbyteArray data_);