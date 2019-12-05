/*
 * Copyright (c) 2019 Cossack Labs Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.cossacklabs.themis;

/**
 * Internal Themis error.
 *
 * @see ThemisRuntimeException unchecked variant
 */
public class ThemisException extends Exception {

    // Keep in sync with <themis/themis_error.h>
    public static final int THEMIS_SUCCESS              = 0;
    public static final int THEMIS_FAIL                 = 11;
    public static final int THEMIS_INVALID_PARAMETER    = 12;
    public static final int THEMIS_NO_MEMORY            = 13;
    public static final int THEMIS_BUFFER_TOO_SMALL     = 14;
    public static final int THEMIS_DATA_CORRUPT         = 15;
    public static final int THEMIS_INVALID_SIGNATURE    = 16;
    public static final int THEMIS_NOT_SUPPORTED        = 17;
    // The following codes are context-dependent
    public static final int THEMIS_SSESSION_KA_NOT_FINISHED = 19;
    public static final int THEMIS_SSESSION_TRANSPORT_ERROR = 20;
    public static final int THEMIS_SSESSION_GET_PUB_FOR_ID_CALLBACK_ERROR = 21;
    public static final int THEMIS_SSESSION_SEND_OUTPUT_TO_PEER = 1;
    public static final int THEMIS_SCOMPARE_SEND_OUTPUT_TO_PEER = 1;
    public static final int THEMIS_SCOMPARE_MATCH       = 21;
    public static final int THEMIS_SCOMPARE_NO_MATCH    = 22;
    public static final int THEMIS_SCOMPARE_NOT_READY   = 0;

    static String toString(int errorCode) {
        switch (errorCode) {
            case THEMIS_SUCCESS:
                return "success";
            case THEMIS_FAIL:
                return "failure";
            case THEMIS_INVALID_PARAMETER:
                return "invalid parameter";
            case THEMIS_NO_MEMORY:
                return "out of memory";
            case THEMIS_BUFFER_TOO_SMALL:
                return "buffer too small";
            case THEMIS_DATA_CORRUPT:
                return "corrupted data";
            case THEMIS_INVALID_SIGNATURE:
                return "invalid signature";
            case THEMIS_NOT_SUPPORTED:
                return "operation not supported";
            default:
                return "unknown error: " + errorCode;
        }
    }

    private final int errorCode;

    /**
     * Constructs an exception from error code with default message.
     */
    ThemisException(int errorCode) {
        super(toString(errorCode));
        this.errorCode = errorCode;
    }

    /**
     * Constructs an exception from error code and explanatory message.
     */
    ThemisException(String message, int errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    /**
     * Returns raw Themis error code.
     *
     * @see ThemisException error code constants
     */
    public final int getErrorCode() {
        return errorCode;
    }
}
