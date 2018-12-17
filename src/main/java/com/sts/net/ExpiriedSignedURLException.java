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
public class ExpiriedSignedURLException extends Exception{
    public ExpiriedSignedURLException( final String msg)
    {
        super( msg);
    }
}
