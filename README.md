# sloth【树懒-闪电⚡️】
安全以及高性能加解密集合库[持续更新中..]

### 简介
sloth是基于开源跨平台加解密库openssl实现的一系列加解密算法API，本功能适用于Android项目,兼容arm,x86平台；

### 导入SDK

1.在项目的根目录build.gradle中的repositories 添加:
```

repositories {
        jcenter()
    }

```
2.然后在模块的build.gradle(Module) 的 dependencies 添加:
```

dependencies {
      compile 'com.bulinbulin:sloth:1.0.0'
    }

```



### 接口方法

```
/**
 * 生成国密sm2的公私钥对
 * @return KeyPairInfo对象
 */
public native KeyPairInfo createKeyPair();
```
&nbsp;
```
/**
 * sm2加密算法，以C1C2C3模式拼接返回，采用推荐曲线
 * @param data  需要加密内容
 * @param key   加密的公钥，长度为64字节
 * @return      加密后经过hex编码后返回
 */
public native byte[] sm2Encrypt(String data, byte[] key);
```
&nbsp;
```
/**
 * sm2加密算法，以C1C2C3拼接传入，采用推荐曲线
 * @param data  需要解密的数据，此数据方法内部进行hex解码
 * @param key   解密的私钥，长度为32字节
 * @return  解密后的数据，以byte数组返回
 */
public native byte[] sm2Decrypt(String data, byte[] key);
```

&nbsp;


### Demo实例

请参考Demo 示例，有详细的说明介绍。

