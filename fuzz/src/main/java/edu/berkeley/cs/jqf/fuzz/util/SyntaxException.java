package edu.berkeley.cs.jqf.fuzz.util;

public class SyntaxException extends RuntimeException {
    public SyntaxException(String msg) {
        super(msg);
    }

    public SyntaxException(Throwable e) {
        super(e);
    }

    public SyntaxException(String msg, Throwable e) {
        super(msg, e);
    }
}
