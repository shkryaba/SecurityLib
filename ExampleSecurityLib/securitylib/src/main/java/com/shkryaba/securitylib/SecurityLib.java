package com.shkryaba.securitylib;

public class SecurityLib {

    public native boolean detectXposed();
    public native void JDWPfun();
    public native void antidebug();
    public native byte[] signature();

    static {
        System.loadLibrary("native-lib");
    }
}
