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
import java.text.ParseException;
import java.util.Date;
import java.util.LinkedHashMap;
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
//    private final int port;
    private final @Nonnull String path;
    private final @Nonnull Algorithm algorithm;
    private final @Nonnull String accessKey;
    private final @Nonnull String region;
    private final @Nonnull String service;
    private final @Nonnull String givenSignature;
    private final int expires;
//    private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
    private final LinkedHashMap<String, String> parameters;
    private final @Nonnull Date date;
    
    public enum Algorithm{
        STS1_HMAC_SHA256("STS1-HMAC-SHA256","X-sts-", ""),
        APA1_HMAC_SHA256("APA1-HMAC-SHA256","X-apat-", ""),
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
//        final int port,
        final @Nonnull Algorithm algorithm,
        final @Nonnull String accessKey,
        final @Nonnull String region,
        final @Nonnull String service,
        final @Nonnull Date date,
        final int expires,
        final @Nonnull String givenSignature,
        final LinkedHashMap<String, String> parameters
    )
    {
        this.method=method;
        this.host=host;
        if( host == null ) throw new IllegalArgumentException("host is mandatory");
        if( host.matches("^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9])\\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\\-]*[A-Za-z0-9])(|:[0-9]+)$") == false )
        {
            throw new IllegalArgumentException("invalid host: " + host);
        }
        this.protocol=protocol;
//        this.port=port;
        this.path=path;
        this.algorithm=algorithm;
        this.accessKey=accessKey;
        this.region=region;
        this.service=service;
        this.date=date;
        this.expires=expires;
        this.givenSignature=givenSignature;
        this.parameters=parameters;
    }
    
    public String findValid( final String... keys) throws ExpiriedSignedURLException, NoMatchingSignatureException
    {
        long now=System.currentTimeMillis();
        
        if( date.getTime()>now)
        {
            throw new ExpiriedSignedURLException( "Not valid for " + TimeUtil.getDiff(now, date.getTime()));
        }
        
        if( expires > 0 && now > date.getTime() + expires * 1000l)
        {
            throw new ExpiriedSignedURLException( "Expired " + TimeUtil.getDiff(date) + " ago");
        }
        
        for( String key:keys)
        {
            StringBuilder algorithmBuilder=new StringBuilder();
            String checkSignature=calculateSignature( key,algorithmBuilder);
            
            if( givenSignature.equals( checkSignature))
            {
                return key;
            }
                
        }
        
        throw new NoMatchingSignatureException( "No match found");
    }
    
    private String calculateSignature(final @Nonnull String secretKey, final @Nonnull StringBuilder algorithmBuilder)
    {
        
        /*
        GET
        /test.txt
        X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host
        host:examplebucket.s3.amazonaws.com

        host
        UNSIGNED-PAYLOAD
        */
        String canonicalRequest=method.name()+"\n";
        
        if( path!=null)
        {
            canonicalRequest+=path+"\n";
        }
        algorithmBuilder.append(algorithm.nameSpace).append("Algorithm=").append(algorithm.value);
        
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
        
        algorithmBuilder.append("&").append(algorithm.nameSpace).append("Credential=").append(StringUtilities.encode(credential).replace("%2f", "%2F"));
        
        String ds = TimeUtil.format("yyyyMMdd'T'HHmmss'Z'", date, null);
        algorithmBuilder.append("&").append(algorithm.nameSpace).append("Date=").append(ds);

        if( expires > 0)
        {
            algorithmBuilder.append("&").append(algorithm.nameSpace).append("Expires=").append(expires);
        }
        
        if( algorithm == Algorithm.AWS4_HMAC_SHA256)
        {
            algorithmBuilder.append("&X-Amz-SignedHeaders=host");
        }
        
        canonicalRequest+=algorithmBuilder+"\n";
        
        for( String name:parameters.keySet())
        {
            String value=parameters.get(name);
            canonicalRequest+=StringUtilities.encode(name)+":" + StringUtilities.encode(value)+"\n";
            
        }
        if( host.contains(":"))
        {
            int pos = host.indexOf(":");
            canonicalRequest+="host:" + host.substring(0, pos) +"\n";
        }
        else
        {
            canonicalRequest+="host:" + host +"\n";
        }
        canonicalRequest+=  "\nhost\n" +
                            "UNSIGNED-PAYLOAD";

        String canonicalRequestHex=calculateSHA256(canonicalRequest);
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
        
        String stringToSign=algorithm.value+"\n"+
            ds+"\n"+
            scope +"\n"+
            canonicalRequestHex;

        String signature=StringUtilities.toHexString(calculateHMACSHA256(signingKey,stringToSign.getBytes()));
        
        return signature;
    }
    public URL generate( final @Nonnull String secretKey)
    {
        if( StringUtilities.isBlank(secretKey))
        {
            throw new IllegalArgumentException("Secret key must not be blank");
        }
        
        String tempURL=protocol + "://" + host;
        if( path!=null)
        {
            tempURL+= path;
        }

        

        StringBuilder algorithmBuilder=new StringBuilder();
        
        String signature=calculateSignature( secretKey,algorithmBuilder);
        tempURL+="?" + algorithmBuilder;
        
        
        tempURL+="&" +algorithm.nameSpace +"Signature="+signature;

        for( String name:parameters.keySet())
        {
            String value=parameters.get(name);
            tempURL+="&" +StringUtilities.encode(name)+"=" + StringUtilities.encode(value);            
        }
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
//    
//    @Nonnull @CheckReturnValue
//    private String calculateRFC2104HMAC(final @Nonnull String data, final @Nonnull String key)
//    {
//        try{
//            SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), HMAC_SHA1_ALGORITHM);
//            Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
//            mac.init(signingKey);
//            return new String(StringUtilities.encodeBase64(mac.doFinal(data.getBytes())));
//        }
//        catch( IllegalStateException | InvalidKeyException | NoSuchAlgorithmException e)
//        {
//            throw CLogger.rethrowRuntimeExcepton(e);
//        }
//    }
    
    /**
     * Create a builder.
     * @param method the method.
     * @param protocol the protocol
     * @param host the host
     * @param path the path
     * @return
     */
    public static Builder builder(final @Nonnull Method method, final @Nonnull String protocol, final @Nonnull String host, final @Nonnull String path)//, final @Nonnegative int port)
    {
        return new Builder(method, protocol, host, path);//,port);
    }
    
    /**
     * Create a builder.
     * @param method the method.
     * @param protocol the protocol
     * @param host the host
     * @param path the path
     * @return
     */
//    public static Builder builder(final @Nonnull Method method, final @Nonnull String protocol, final @Nonnull String host, final @Nonnull String path)
//    {
//        return new Builder(method, protocol, host, path);//,0);
//    }
    
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

//        int port=url.getPort();
//        if( port <0)port=0;
        Builder b= builder(method, url.getProtocol(), url.getHost(), url.getPath());//, port);
        
        String query=url.getQuery();
        if( StringUtilities.notBlank(query))
        {
            for( String nameValuePair:query.split("&"))
            {
                int pos=nameValuePair.indexOf("=");
                
                String name;
                String value;
                
                if( pos!=-1)
                {
                    name=StringUtilities.decode(nameValuePair.substring(0, pos));
                    value=StringUtilities.decode(nameValuePair.substring(pos+1));
                }
                else
                {
                    name=StringUtilities.decode(nameValuePair);
                    value="";
                }
                
                b.addParameter( name, value);
                
            }
        }
        

        return b;
    }
    
    public static class Builder{
        private final Method method;
        private final String protocol;
        private final String host; 
//        private final int port;
        private final String path;
        private String accessKey="guest";
        private String region="";
        private String service="";
        private Date date=new Date();
        private int expires;
        private String expectedSignature="";
        private Algorithm algorithm=Algorithm.STS1_HMAC_SHA256;
        private final LinkedHashMap<String, String> parameters=new LinkedHashMap<>();
        
        private Builder(final @Nonnull Method method, final @Nonnull String protocol, final @Nonnull String host, final @Nullable String path)//, final int port)
        {
            if( protocol.matches("http(|s)")==false)
            {
                throw new IllegalArgumentException("Protocol must be http or https was: " + protocol);
            }
            if( StringUtilities.isBlank(host))
            {
                throw new IllegalArgumentException("host must not be blank" );
            }
//            if( port < 0)
//            {
//                throw new IllegalArgumentException("port must not be negative was: " + port );
//            }
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
//            this.port=port;
        }
        
        public Builder addParameter( final @Nonnull String name, final @Nonnull String value)
        {
            if( name.matches("X-[a-z]{3}-.+"))
            {
                if( name.endsWith("Algorithm"))
                {
                    boolean found=false;
                    for( Algorithm a: Algorithm.values())
                    {
                        if( a.value.equals( value))
                        {
                            setAlgorithm(a);      
                            found=true;
                        }
                    }
                    
                    if( found==false)
                    {
                        throw new IllegalArgumentException("No algorithm: " + value);
                    }
                }
                else if( name.endsWith("Date"))
                {
                    try{
                        Date d=TimeUtil.parse("yyyyMMdd'T'HHmmss'Z'", value, null);
                        setDate(d);
                    }
                    catch( ParseException pe)
                    {
                        throw new IllegalArgumentException( "not a date parsible string was: " + value, pe);
                    }
                }
                else if( name.endsWith("Credential"))
                {
                    int pos=value.indexOf("/");
                    if( pos!=-1)
                    {
                        String tmpAccessKey=value.substring(0, pos);
                        setAccessKey(tmpAccessKey);
                        
                        int start=pos+1;
                        int end=value.indexOf("/", start);
                        
                        if( end!=-1)
                        {
                            String tmpRegion=value.substring(start, end);
                            setRegion(tmpRegion);
                            
                            start = end+1;
                            end=value.indexOf("/", start);
                            
                            if( end!=-1)
                            {
                                String tmpService=value.substring(start, end);
                                setService(tmpService);
                            }
                        }
//                        else
//                        {
//                            
//                        }
                    }
                    else
                    {
                        throw new IllegalArgumentException("Invalid Credential: " + value);
                    }
                }                
                else if( name.endsWith("Expires"))
                {
                    setExpires(Integer.parseInt(value));
                }
                else if( name.endsWith("Signature"))
                {
                    setSignature(value);
                }
                else
                {
                    parameters.put(name, value);
                }
//                                    + "X-Amz-Algorithm=AWS4-HMAC-SHA256&"
//            + "X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&"
//                + "X-Amz-Date=20130524T000000Z&"
//                + "X-Amz-Expires=86400&"
//            + "X-Amz-SignedHeaders=host&"
//                + "X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404";
            }
            else
            {
                parameters.put(name, value);
            }
            return this;
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
        public Builder setSignature( final @Nonnull String signature )
        {
            if( StringUtilities.isBlank(signature))
            {
                throw new IllegalArgumentException("signature is mandatory");
            }
            this.expectedSignature=signature;
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
            return new SignedURL(method, protocol, host, path, algorithm,accessKey,region,service,date,expires,expectedSignature, parameters);
        }
    } 
}
