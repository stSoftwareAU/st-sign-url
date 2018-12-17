/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sts.net;

/**
 *
 * @author nigel
 */
public class NoMatchingSignatureException extends Exception{
    public NoMatchingSignatureException( final String msg)
    {
        super( msg);
    }
}
