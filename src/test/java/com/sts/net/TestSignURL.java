/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sts.net;
import com.aspc.remote.rest.Method;
import com.aspc.remote.util.misc.TimeUtil;
import java.net.URL;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import junit.framework.TestCase;
/**
 *
 * @author nigel
 */
public class TestSignURL extends TestCase{
    public void testSimple() throws ParseException
    {
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
    
    public void testCreateLocal() throws Exception
    {
        URL tempURL=new URL("http://localhost:8080");

        String sessionID="gfK8iKNeOksZV7c6qFjigq_fwWI3AY2tSg3RowwI";
        
        Date date=TimeUtil.parse("yyyyMMdd'T'HHmmss'Z'", "20190415T082245Z", null);
        
        
        URL url=SignedURL.builder(
            Method.GET,
            tempURL.getProtocol(),
            tempURL.getHost()+":" + tempURL.getPort(),
            "/ReST/v1/onix/export")
            .setAlgorithm(SignedURL.Algorithm.STS1_HMAC_SHA256 )
            .addParameter("version", "3")
            .setDate(date)
            .addParameter("recordReference", "139-9781419719806")
            .addParameter("LAYERID",Integer.toString( 2021))
            .setAccessKey("nigel")
            .create()
            .generate(sessionID);

        String expectedURL="http://localhost:8080/ReST/v1/onix/export?X-sts-Algorithm=STS1-HMAC-SHA256&X-sts-Credential=nigel%2F20190415&X-sts-Date=20190415T082245Z&X-sts-Signature=b0a829015959c62cf414adafeb03077e36ee5b723b0eb03e37dea9e5c1394d5f&version=3&recordReference=139-9781419719806&LAYERID=2021";
        String actualURL= url.toString();
        
        assertEquals( "match URL",expectedURL,actualURL );
        
        
        SignedURL.builder(Method.GET, url).create().findValid(sessionID);
    }
    
    
    public void testValidFor7Days() throws ExpiriedSignedURLException, NoMatchingSignatureException
    {
        SignedURL su=SignedURL.builder(Method.GET, "https", "demo1.jobtrack.com.au", "/test.txt")
//                .setAlgorithm(SignedURL.Algorithm.AWS4_HMAC_SHA256)
                .setAccessKey("admin")
//                .setRegion("us-east-1")
//                .setService("s3")
                .setExpires(86400)
//                .setDate(date)
                .create();
        
        String secretKey="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        
        URL url=su.generate(secretKey);
        
        SignedURL su2=SignedURL.builder(Method.GET, url).create();
        URL url2=su2.generate(secretKey);
        
        assertEquals( "match URLs", url.toString(), url2.toString());
        
        String foundKey=su2.findValid("abc", secretKey);
        
        assertEquals( "found match", secretKey, foundKey);
    }    
    
    public void testExpired() throws ExpiriedSignedURLException, NoMatchingSignatureException, InterruptedException
    {
        SignedURL su=SignedURL.builder(Method.GET, "https", "demo1.jobtrack.com.au", "/test.txt")
//                .setAlgorithm(SignedURL.Algorithm.AWS4_HMAC_SHA256)
                .setAccessKey("admin")
//                .setRegion("us-east-1")
//                .setService("s3")
                .setExpires(1)
//                .setDate(date)
                .create();
        
        String secretKey="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        
        URL url=su.generate(secretKey);
        
        SignedURL su2=SignedURL.builder(Method.GET, url).create();
        URL url2=su2.generate(secretKey);
        
        assertEquals( "match URLs", url.toString(), url2.toString());
        Thread.sleep(2000);
        try{
            su2.findValid("abc", secretKey);
            fail( "Should have expired");
        }
        catch( ExpiriedSignedURLException ese)
        {
            // Expected. 
        }
    }
    
    
    public void testValidParameters() throws Exception
    {
        SignedURL su=SignedURL.builder(Method.GET, "https", "demo1.jobtrack.com.au", "/test.txt")
//                .setAlgorithm(SignedURL.Algorithm.AWS4_HMAC_SHA256)
                .setAccessKey("admin")
//                .setRegion("us-east-1")
//                .setService("s3")
//                .setExpires(86400)
//                .setDate(date)
                .addParameter("X", "1")
                .addParameter("Y", "2")
                .addParameter("Z", "3")
                .create();
        
        String secretKey="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        
        URL url=su.generate(secretKey);
        
        SignedURL su2=SignedURL.builder(Method.GET, url).create();
        
        String foundKey=su2.findValid("abc", secretKey);
        
        assertEquals( "found match", secretKey, foundKey);


        
        URL url3=new URL( url.toString().replace("X=1", "X=2"));
        
        SignedURL su3=SignedURL.builder(Method.GET, url3).create();

        try
        {
            su3.findValid("abc", secretKey);
            fail( "Should not have a valid key: " + url3);
        }
        catch( NoMatchingSignatureException nmse)
        {
            // Expected.
        }
    }    
    
    
}
