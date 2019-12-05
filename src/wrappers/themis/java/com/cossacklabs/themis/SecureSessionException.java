/*
* Copyright (c) 2015 Cossack Labs Limited
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

public class SecureSessionException extends ThemisException {

    public SecureSessionException() {
        super(ThemisException.THEMIS_FAIL);
    }

    public SecureSessionException(String message) {
        super(message, ThemisException.THEMIS_FAIL);
    }

    // The above constructors were historically public
    // and kept that way for compatibility.

    static String toString(int errorCode) {
        switch (errorCode) {
            case THEMIS_SSESSION_SEND_OUTPUT_TO_PEER:
                return "send key agreement data to peer";
            case THEMIS_SSESSION_KA_NOT_FINISHED:
                return "key agreement not finished";
            case THEMIS_SSESSION_TRANSPORT_ERROR:
                return "transport layer error";
            case THEMIS_SSESSION_GET_PUB_FOR_ID_CALLBACK_ERROR:
                return "failed to get public key for ID";
            default:
                return ThemisException.toString(errorCode);
        }
    }

    SecureSessionException(int errorCode) {
        super(toString(errorCode), errorCode);
    }

    SecureSessionException(String message, int errorCode) {
        super(message, errorCode);
    }
}
