/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sts.net;

import com.aspc.remote.rest.Method;
import com.aspc.remote.util.misc.CLogger;
import com.aspc.remote.util.misc.StringUtilities;
import com.aspc.remote.util.misc.TimeUtil;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnegative;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html#query-string-auth-v4-signing
 * 
 * @author nigel
 */
public class SignedURL {
    private final @Nonnull Method method;
    private final @Nonnull String protocol;
    private final @Nonnull String host; 
    private final int port;
    private final @Nonnull String path;
    private final @Nonnull Algorithm algorithm;
    private final @Nonnull String accessKey;
    private final @Nonnull String region;
    private final @Nonnull String service;
    private final int expires;
    private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";

    private final @Nonnull Date date;
    
    public enum Algorithm{
        STS1_HMAC_SHA256("STS1-HMAC-SHA256","X-sts-", ""),
        AWS4_HMAC_SHA256("AWS4-HMAC-SHA256","X-Amz-", "aws4_request");
        
        public final String value;
        /** the name space for this algorithm. */
        public final String nameSpace;
        public final String requestType;
        
        private Algorithm( final String value, final String nameSpace, final String requestType)
        {
            this.value=value;
            this.nameSpace=nameSpace;
            this.requestType=requestType;
        }
    }
    private SignedURL(
        final @Nonnull Method method, 
        final @Nonnull String protocol, 
        final @Nonnull String host, 
        final @Nullable String path, 
        final int port,
        final @Nonnull Algorithm algorithm,
        final @Nonnull String accessKey,
        final @Nonnull String region,
        final @Nonnull String service,
        final @Nonnull Date date,
        final int expires
    )
    {
        this.method=method;
        this.host=host;
        this.protocol=protocol;
        this.port=port;
        this.path=path;
        this.algorithm=algorithm;
        this.accessKey=accessKey;
        this.region=region;
        this.service=service;
        this.date=date;
        this.expires=expires;
    }
    
    public URL generate( final @Nonnull String secretKey)
    {
        if( StringUtilities.isBlank(secretKey))
        {
            throw new IllegalArgumentException("Secret key must not be blank");
        }
        
        /*
        GET
        /test.txt
        X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host
        host:examplebucket.s3.amazonaws.com

        host
        UNSIGNED-PAYLOAD
        */
        String canonicalRequest=method.name()+"\n";
        
        String tempURL=protocol + "://" + host;
        if( path!=null)
        {
            canonicalRequest+=path+"\n";
            tempURL+= path;
        }
        String tempAlgorithm=algorithm.nameSpace + "Algorithm="+ algorithm.value;
        
        String credential=accessKey;
        String yyyyMMdd=TimeUtil.format("yyyyMMdd", date, null);
        String scope= yyyyMMdd;

        if( StringUtilities.notBlank(region)) 
        {
            scope+="/" +region;
        }
        if( StringUtilities.notBlank(service))
        {
            scope+="/" +service;
        }
        if( StringUtilities.notBlank(algorithm.requestType))
        {
            scope+="/" +algorithm.requestType;
        }
        credential+="/" + scope;
        
        tempAlgorithm+="&" +algorithm.nameSpace + "Credential="+ StringUtilities.encode(credential).replace("%2f", "%2F");
        
        String ds = TimeUtil.format("yyyyMMdd'T'HHmmss'Z'", date, null);
        tempAlgorithm+="&" +algorithm.nameSpace + "Date="+ ds;

        if( expires > 0)
        {
            tempAlgorithm+="&" +algorithm.nameSpace + "Expires="+ expires;
        }
        
        if( algorithm == Algorithm.AWS4_HMAC_SHA256)
        {
            tempAlgorithm+="&X-Amz-SignedHeaders=host";
        }
        
        canonicalRequest+=tempAlgorithm+"\n";
        canonicalRequest+="host:" + host+"\n";
        canonicalRequest+=  "\nhost\n" +
                            "UNSIGNED-PAYLOAD";

        String canonicalRequestHex=calculateSHA256(canonicalRequest);
        
        tempURL+="?" + tempAlgorithm;
        
        String stringToSign=algorithm.value+"\n"+
                ds+"\n"+
                scope +"\n"+
                canonicalRequestHex;
        
        
        byte[] signingKey=calculateHMACSHA256((algorithm.value.substring(0,4) + secretKey).getBytes(), yyyyMMdd.getBytes());
        if( StringUtilities.notBlank(region)) 
        {
            signingKey=calculateHMACSHA256(signingKey, region.getBytes());
        }
        if( StringUtilities.notBlank(service))
        {
            signingKey=calculateHMACSHA256(signingKey, service.getBytes());
        }
        if( StringUtilities.notBlank(algorithm.requestType))
        {
            signingKey=calculateHMACSHA256(signingKey, algorithm.requestType.getBytes());
        }
        
        String signature=StringUtilities.toHexString(calculateHMACSHA256(signingKey,stringToSign.getBytes()));
        
        tempURL+="&" +algorithm.nameSpace +"Signature="+signature;

        try {
            return new URL(tempURL);
        } catch (MalformedURLException ex) {
            throw new IllegalArgumentException("invalid URL: " + tempURL);
        }
    }
    
    private byte[] calculateHMACSHA256( final byte key[], final byte data[])
    {
        try{
            final Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
            final SecretKeySpec secret_key = new javax.crypto.spec.SecretKeySpec(key, "HmacSHA256");
            sha256_HMAC.init(secret_key);
            final byte[] mac_data = sha256_HMAC.doFinal(data);

            return mac_data;
        }
        catch( NoSuchAlgorithmException | InvalidKeyException nsa)
        {
            throw CLogger.rethrowRuntimeExcepton(nsa);
        }
    }
    
    private String calculateSHA256( final String data)
    {
        try{
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedhash = digest.digest(
                data.getBytes(StandardCharsets.UTF_8)
            );

            return StringUtilities.toHexString(encodedhash);
        }
        catch( NoSuchAlgorithmException nsa)
        {
            throw CLogger.rethrowRuntimeExcepton(nsa);
        }
    }
    
    @Nonnull @CheckReturnValue
    private String calculateRFC2104HMAC(final @Nonnull String data, final @Nonnull String key)
    {
        try{
            SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), HMAC_SHA1_ALGORITHM);
            Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
            mac.init(signingKey);
            return new String(StringUtilities.encodeBase64(mac.doFinal(data.getBytes())));
        }
        catch( IllegalStateException | InvalidKeyException | NoSuchAlgorithmException e)
        {
            throw CLogger.rethrowRuntimeExcepton(e);
        }
    }
    
    /**
     * Create a builder.
     * @param method the method.
     * @param protocol the protocol
     * @param host the host
     * @param port the port
     * @param path the path
     * @return
     */
    public static Builder builder(final @Nonnull Method method, final @Nonnull String protocol, final @Nonnull String host, final @Nonnull String path, final @Nonnegative int port)
    {
        return new Builder(method, protocol, host, path,port);
    }
    
    /**
     * Create a builder.
     * @param method the method.
     * @param protocol the protocol
     * @param host the host
     * @param path the path
     * @return
     */
    public static Builder builder(final @Nonnull Method method, final @Nonnull String protocol, final @Nonnull String host, final @Nonnull String path)
    {
        return new Builder(method, protocol, host, path,0);
    }
    
    /**
     * Create a builder.
     * @param method the method
     * @param url the URL.

     * @return
     */
    public static Builder builder(final @Nonnull Method method, final @Nonnull URL url)
    {
        String userInfo=url.getUserInfo();
        if( StringUtilities.notBlank(userInfo))
        {
            throw new IllegalArgumentException("URL must not include user info was: " + userInfo);
        }
        String query=url.getQuery();
        if( StringUtilities.notBlank(query))
        {
            throw new IllegalArgumentException("URL must not include query was: " + query);
        }
        return builder(method, url.getProtocol(), url.getHost(), url.getFile(), url.getPort());
    }
    
    public static class Builder{
        private final Method method;
        private final String protocol;
        private final String host; 
        private final int port;
        private final String path;
        private String accessKey="guest";
        private String region="";
        private String service="";
        private Date date=new Date();
        private int expires;
        
        private Algorithm algorithm=Algorithm.STS1_HMAC_SHA256;
        
        private Builder(final @Nonnull Method method, final @Nonnull String protocol, final @Nonnull String host, final @Nullable String path, final int port)
        {
            if( protocol.matches("http(|s)")==false)
            {
                throw new IllegalArgumentException("Protocol must be http or https was: " + protocol);
            }
            if( StringUtilities.isBlank(host))
            {
                throw new IllegalArgumentException("host must not be blank" );
            }
            if( port < 0)
            {
                throw new IllegalArgumentException("port must not be negative" );
            }
            if( path==null || path.equals(""))
            {
                this.path=null;
            }
            else if( path.matches("/[^?#&]*") ==false)
            {
                throw new IllegalArgumentException("path invalid was: " + path);
            }
            else
            {
                this.path=path;                
            }
            this.method=method;
            this.host=host;
            this.protocol=protocol;
            this.port=port;
        }
        
        @Nonnull
        public Builder setAccessKey( final @Nonnull String accessKey )
        {
            if( StringUtilities.isBlank(accessKey))
            {
                throw new IllegalArgumentException("accessKey is mandatory");
            }
            this.accessKey=accessKey;
            return this;
        }
                
        @Nonnull
        public Builder setRegion( final @Nonnull String region )
        {
            if( StringUtilities.isBlank(region))
            {
                throw new IllegalArgumentException("domain is mandatory");
            }
            this.region=region;
            return this;
        }
                            
        @Nonnull
        public Builder setExpires( final @Nonnegative int expires )
        {
            if( expires <0)
            {
                throw new IllegalArgumentException("Expires must not be negative");
            }
            this.expires=expires;
            return this;
        }     
        
        @Nonnull
        public Builder setService( final @Nonnull String service )
        {
            if( StringUtilities.isBlank(service))
            {
                throw new IllegalArgumentException("service is mandatory");
            }
            this.service=service;
            return this;
        }
        
        @Nonnull
        public Builder setAlgorithm( final @Nonnull Algorithm algorithm )
        {
            if( algorithm==null)
            {
                throw new IllegalArgumentException("algorthum is mandatory");
            }
            this.algorithm=algorithm;
            return this;
        }
        
        @Nonnull
        public Builder setDate( final @Nonnull Date date )
        {
            if( date==null)
            {
                throw new IllegalArgumentException("date is mandatory");
            }
            this.date=date;
            return this;
        }
        
        @Nonnull @CheckReturnValue
        public SignedURL create()
        {
            return new SignedURL(method, protocol, host, path, port,algorithm,accessKey,region,service,date,expires);
        }
    } 
}
