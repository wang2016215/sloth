package com.bulinbulin.security;

public class KeyPairInfo {
    /**
     * 公钥，hex后长度为130，开头为04
     */
    private String pubk ;

    /**
     * 私钥，hex后长度为64
     */
    private String prik ;

    public String getPubk(){
        return pubk;
    }

    public String getPrik(){
        return prik;
    }

}
