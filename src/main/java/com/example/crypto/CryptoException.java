package com.example.crypto;

public class CryptoException extends RuntimeException {
    public CryptoException(Exception e) {
        super(e);
    }
}
