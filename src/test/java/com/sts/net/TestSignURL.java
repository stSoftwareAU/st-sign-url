/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sts.net;
import com.aspc.remote.rest.Method;
import com.aspc.remote.util.misc.TimeUtil;
import java.text.ParseException;
import java.util.Date;
import junit.framework.TestCase;
/**
 *
 * @author nigel
 */
public class TestSignURL extends TestCase{
    public void testSimple() throws ParseException
    {
        System.out.println( "Hello");
        
        String expected="https://examplebucket.s3.amazonaws.com/test.txt?"
                + "X-Amz-Algorithm=AWS4-HMAC-SHA256&"
                + "X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&"
                + "X-Amz-Date=20130524T000000Z&"
                + "X-Amz-Expires=86400&"
                + "X-Amz-SignedHeaders=host&"
                + "X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404";
        
        Date date=TimeUtil.parse("yyyyMMdd'T'HHmmss'Z'", "20130524T000000Z", null);
                
        SignedURL su=SignedURL.builder(Method.GET, "https", "examplebucket.s3.amazonaws.com", "/test.txt")
                .setAlgorithm(SignedURL.Algorithm.AWS4_HMAC_SHA256)
                .setAccessKey("AKIAIOSFODNN7EXAMPLE")
                .setRegion("us-east-1")
                .setService("s3")
                .setExpires(86400)
                .setDate(date)
                .create();
        
        String secretKey="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        
        String actual=su.generate(secretKey).toString();
        System.out.println( actual);
        assertEquals( "signed URL", expected, actual);
    }
}
