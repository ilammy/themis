package com.cossacklabs.themis;

public class SecureCompareException extends ThemisException {

    static String toString(int errorCode) {
        switch (errorCode) {
            case THEMIS_SCOMPARE_SEND_OUTPUT_TO_PEER:
                return "send comparison data to peer";
            case THEMIS_SCOMPARE_MATCH:
                return "data matches";
            case THEMIS_SCOMPARE_NO_MATCH:
                return "data does not match";
            case THEMIS_SCOMPARE_NOT_READY:
                return "comparator not ready";
            default:
                return ThemisException.toString(errorCode);
        }
    }

    SecureCompareException() {
        super(ThemisException.THEMIS_FAIL);
    }

    SecureCompareException(int errorCode) {
        super(toString(errorCode), errorCode);
    }

    SecureCompareException(String message, int errorCode) {
        super(message, errorCode);
    }
}
