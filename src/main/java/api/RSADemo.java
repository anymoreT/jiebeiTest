package api; /**
 * Alipay.com Inc.
 * Copyright (c) 2004-2016 All Rights Reserved.
 */

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * 借呗授信申请和结果通知报文加签/验签-SHA256withRSA算法实现demo
 *
 * 算法:SHA256withRSA
 * 密钥长度:2048
 *
 * 加签:
 * 1. 加签内容:request或者response下面所有的内容;(要求:去掉空格和换行)
 * 2. 对加签内容进行base64编码
 * 3. 签名
 * 4. 对签名结果进行base64编码
 *
 * 验签:
 * 1. 验签内容:request或者response下面所有的内容;(要求:去掉空格和换行)
 * 2. 对签名进行base64解码
 * 3. 对验签内容进行base64编码
 * 4. 验签
 *
 * @author yanqing.qyq
 * @version $Id: RSADemo.java, v 0.1 2016-11-21 15:20 yanqing.qyq Exp $$
 */


public class RSADemo {

    /** 默认编码 */
    private static final String DEFAULT_ENCODING = "UTF-8";

    /** 签名算法 */
    private static final String SIG_ALGORITHM    = "SHA256withRSA";

    private static final String LINE_BREAK       = "\r\n";

    /**银行公钥 */
    private PublicKey           bankPublicKey;

    /**支付宝私钥 */
    private PrivateKey          alipayPrivateKey;

    private void init() {

        try {
            String merPriKey = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDl5eloqFM/QEp5kVXTNwmpTlAMpFXqi8V+B43YkUCGANwlpzQKJKY49fHzPRHRQlMX3XtKkXAKYnx7PSOt0sONyMu7HIkD1FOqfeKCcAxuyzCdpwfl4UVZh+HjgWbGCv+AZS43W4rC/KCWlAjuX1rXbwcA9wUap2Yoen75pj0reThoiCbzt6tw9Fboqhfk0EAoTZGpkZ0E3Qpy/eLW+G0fssqVUkOFR5VfYZhUXDceHNxBjXUxrpOZIJ0Vf0Kk280e0bxnOvumyD1syAQ3hsjhfBWxA0B8pxyLuMM462Di1Z0tPF2ul9yD5BG++o3PbeXLARJIbrQFWNkx6AsgZMSlAgMBAAECggEAA2RkEEZDjDBfqPGLCaXLP7NHHRijp+VOEbD819A02oVSuj+AVhH6XebLHiKti5/l5/k9o3kH5S9U1OCvERaGCiaHUwh1wRe18FMRL4mFtXDME9duF2c+hbaqj5fOM2fgIz3a87gnEP93QyGGDDZd+cXKnaoHakBEEp7UFszsJCMLl6v4LbS+ZKV5SFhYMqWHbpxMzwtrHY3Wk/uZr6MpL7LJHJbGpUj1SpPsIBLSS8UTQOJoeO8oxPj/+Noec6cWy6e00TZFgOgtoXLgdgRP2c3njN3DHxKaeebwpVjO+C0s4I3NGhQEm7zORfsGMLTDsURf3gy5NKkux3pR61vBIQKBgQD45lSpmnNizcJVk1WUHfw6VkU2co1ihGnKQKLbKxqS8K8BQA30H7lRf1ERZZPUR4jsFXPkDLBZ8ZUNYUn3+Ce92fKixmZ5ILPhwTZ0q44/DdTsVfIShb99e711WlAoYFx7ZGYeGavGnRTCuojH/7ducNrDxA8JjZBbe6c8gtOuvQKBgQDsdNDIWuAv6epHzRbzwzG383XYm9Imp2Dy8OsiWMepPqREVhc+LDZ8H0eru3AhjniqByBbDDSTGbUjuxE1BtXTxWaFIf948i0Z2X+VIma0J1/ahmaxUUCxMgW/oVT7XAxPp9R8gMVAlr/zeaTSU0x3WAOXNQ+l3ZqTPtSwhUwgCQKBgQCZlsBdnFJhgOjPl8gyS0KO2ReCnrOCPIVvae1U40dVrzG+ysERiNX5ZWAoJQ9Q6gei7yYBbpcQGZRJmmRjoP0dGTWxnk4zpqt5vpmU6xwu6qEeaXakWWYtz8K8fMuD7tqCxhSBtIOcXugltaecCr8tZnSIYx6IXZPb7/Tl0TFA3QKBgCVSKsH01f26BehfToga/vXxz1/o+DpxoLO3ouVA7gKgiHzgubpucAsXRNCuPPyO6CyuA0Vbn9C39gc1t3mPIqDSP2Q0AYatcsDpu2FmlJ9Kt65eGEdUc8mEA7RDWo5x8N+BteAQ0xFmudVMFd+8lg0gLzDmhxm+6G7lM9zIrUNBAoGBAOBCmTjhCMZ1lGNN2LUhLvpRYcDivB3SE9OOC9wi8En4iHg9w0CtXVfJOKTTjPcajLLMtfIPHsRYDTNnSX/ysJGY39W8YKW3S8mCWgBMprAX2wMq1wKA7o+hB+aiKRtPYujjZ3vS/IBdUAl+Vg1Czjw5JLc0fz8nO9zmlnKVlMGr";

            byte[] privateKeys;
            privateKeys = decodeBase64(merPriKey);
            System.out.println("privateKeys" + privateKeys);
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeys);
            System.out.println("privateKeySpec" + privateKeySpec);
            KeyFactory mykeyFactory = KeyFactory
                .getInstance(StringUtils.substringAfter(SIG_ALGORITHM, "with"));

            this.alipayPrivateKey = mykeyFactory.generatePrivate(privateKeySpec);

            String bankPubkey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5eXpaKhTP0BKeZFV0zcJqU5QDKRV6ovFfgeN2JFAhgDcJac0CiSmOPXx8z0R0UJTF917SpFwCmJ8ez0jrdLDjcjLuxyJA9RTqn3ignAMbsswnacH5eFFWYfh44Fmxgr/gGUuN1uKwvyglpQI7l9a128HAPcFGqdmKHp++aY9K3k4aIgm87ercPRW6KoX5NBAKE2RqZGdBN0Kcv3i1vhtH7LKlVJDhUeVX2GYVFw3HhzcQY11Ma6TmSCdFX9CpNvNHtG8Zzr7psg9bMgEN4bI4XwVsQNAfKcci7jDOOtg4tWdLTxdrpfcg+QRvvqNz23lywESSG60BVjZMegLIGTEpQIDAQAB";

            if (bankPubkey != null || bankPubkey.trim().length() != 0) {
                byte[] pubKeys;
                pubKeys = decodeBase64(bankPubkey);
                X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKeys);
                KeyFactory kf = KeyFactory
                    .getInstance(StringUtils.substringAfter(SIG_ALGORITHM, "with"));
                this.bankPublicKey = kf.generatePublic(pubKeySpec);

            }

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    /**
     * 报文签名。
     *
     * @param unsigned 未加密的报文。
     * @return 加密之后的报文。
     */
    public String sign(String unsigned) {

        String signed = null;
        try {

            System.out.println("加签的数据[" + unsigned + "]");

            byte sigData[];
            byte sourceData[] = unsigned.getBytes(DEFAULT_ENCODING);

            //初始化签名
            Signature sig = Signature.getInstance(SIG_ALGORITHM);
            sig.initSign(alipayPrivateKey);
            sig.update(sourceData);

            //1. 签名
            sigData = sig.sign();
            System.out.println("Base64之前的签名[" + sigData + "]");

            //2. 对签名结果进行base64编码
            signed = new String(encodeBase64(sigData));
            System.out.println("Base64之后的签名[" + signed + "]");

        } catch (Exception e) {
            System.out.println("签名异常");
        }
        System.out.println("signed报文签名结果：====等于   " + signed);
        return signed;
    }

    /**
     * 报文验签。
     *
     * @param signed 银行的签名
     * @param unsigned 未签名的源报文
     * @return 验签是否成功
     */
    public boolean verify(String signed, String unsigned) {

        boolean valid = false;
        try {
            byte sourceData[] = unsigned.getBytes(DEFAULT_ENCODING);

            //base64解密
            byte[] sigData = decodeBase64(signed);
            //初始化签名
            Signature sig = Signature.getInstance(SIG_ALGORITHM);
            sig.initVerify(bankPublicKey);
            sig.update(sourceData);

            //验签
            valid = sig.verify(sigData);
        } catch (Exception e) {
            System.out.println("[PointExpressRsaCertifier]签名异常");
        }

        System.out.println("valid验签结果=====  " + valid);

        return valid;

    }

    public static void main(String[] args) {

        RSADemo teste = new RSADemo();
        teste.init();
        //1. 加签内容:request或者response下面所有的内容;(要求:去掉空格和换行)
        String request = "<head><version>1.0.0</version><appId>ALIPAY</appId><function>ant.jiebei.pcapplycore.credit.apply</function><reqTime>20161120104552</reqTime><reqTimeZone>Asia/Shanghai</reqTimeZone><reqMsgId>20161120110400030001701058431001</reqMsgId><reserve></reserve><signType>RSA</signType><inputCharset>UTF-8</inputCharset></head><body><applyNo>201606120000000135A</applyNo><certType>01</certType><certNo>340822199105180249</certNo><name>熊小咖</name><mobileNo>13223456543</mobileNo><extInfo></extInfo></body>";
        //2. 对加签内容进行base64处理
        try {
            String signed = teste.sign(encodeBase64(request.getBytes(DEFAULT_ENCODING)));
            teste.verify(signed, encodeBase64(request.getBytes(DEFAULT_ENCODING)));
        } catch (Exception e) {
            System.out.println("签名异常");
        }

    }

    public static void check() {

        RSADemo teste = new RSADemo();
        teste.init();
        //1. 加签内容:request或者response下面所有的内容;(要求:去掉空格和换行)
        String request = "<head><version>1.0.0</version><appId>ALIPAY</appId><function>ant.jiebei.pcapplycore.credit.apply</function><reqTime>20161120104552</reqTime><reqTimeZone>Asia/Shanghai</reqTimeZone><reqMsgId>20161120110400030001701058431001</reqMsgId><reserve></reserve><signType>RSA</signType><inputCharset>UTF-8</inputCharset></head><body><applyNo>201606120000000135A</applyNo><certType>01</certType><certNo>340822199105180249</certNo><name>熊小咖</name><mobileNo>13223456543</mobileNo><extInfo></extInfo></body>";
        //2. 对加签内容进行base64处理
        try {
            String signed = teste.sign(encodeBase64(request.getBytes(DEFAULT_ENCODING)));
            teste.verify(signed, encodeBase64(request.getBytes(DEFAULT_ENCODING)));
            System.out.print(signed);
        } catch (Exception e) {
            System.out.println("签名异常");
        }

    }

    /**
     * Base64解码
     */
    public static byte[] decodeBase64(String str) {
        Base64 base64 = new Base64();
        return base64.decode(str.getBytes());
    }

    /**
     * Base64编码
     */
    public static String encodeBase64(byte[] b) {
        Base64 base64 = new Base64();
        return new String(base64.encode(b));
    }

    public static String get_institution_credit_apply(String certNo, String name, String mobileNo){
        String request_origin  = "<head><version>1.0.0</version><appId>ALIPAY</appId><function>" +
                "ant.jiebei.institution.credit.apply" +
                "</function>" +
                "<reqTime>" +
                 Uitl.getReqTime() +
                "</reqTime>" +
                "<reqTimeZone>" +
                "UTC+8" +
                "</reqTimeZone>" +
                "<reqMsgId>" +
                 Uitl.getReqMsgId() +
                "</reqMsgId>" +
                "<reserve>" +
                "</reserve>" +
                "<signType>" +
                "RSA" +
                "</signType>" +
                "<inputCharset>" +
                "UTF-8" +
                "</inputCharset>" +
                "</head>" +
                "<body>" +
                "<applyNo>" +
                 Uitl.getReqMsgId() + "A" +
                "</applyNo>" +
                "<applyAmt>0</applyAmt>" +
                "<certType>" +
                "01" +
                "</certType>" +
                "<certNo>" +
                 certNo +
                "</certNo>" +
                "<name>" +
                   name  +
                "</name>" +
                "<mobileNo>" +
                  mobileNo +
                "</mobileNo>" +
                "<zmAuthFlag>Y</zmAuthFlag>" +
                "<extInfo>" +
                "</extInfo>" +
                "</body>";
        RSADemo teste = new RSADemo();
        teste.init();
        String signed = null;
        try {
            signed = teste.sign(encodeBase64(request_origin.getBytes(DEFAULT_ENCODING)));
            teste.verify(signed, encodeBase64(request_origin.getBytes(DEFAULT_ENCODING)));
          //  System.out.print(signed);
        } catch (Exception e) {
            System.out.println("签名异常");
        }
       String  request = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                   "<document>" +
                   "<request>" +
                   request_origin +
                   "</request>" +
                  "<signature>" +
                   signed +
                  "</signature>" +
                "</document>";

        return request;
    }


}
