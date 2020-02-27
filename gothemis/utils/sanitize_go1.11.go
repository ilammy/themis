// +build !go1.12

/*
 * Copyright (c) 2020 Cossack Labs Limited
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

package utils

// SanitizeBuffer applies a workaround for CGo 1.11 and earlier.
//
// This function is an internal implementation detail and may be removed without prior notice.
func SanitizeBuffer(data []byte) []byte {
	if data == nil {
		return nil
	}
	// Copying the data before passing it into CGo avoids the problem.
	d := make([]byte, len(data))
	copy(d, data)
	return d
}

// In Go 1.11 and earlier we need to make a copy for unsafe.Pointer()
// to work correctly with CGo. Since SafeBuffer may be used for sensitive
// data, we take care to zero out our copy when it's no longer needed.

func (buffer *SafeBuffer) maybeCopy(bytes []byte) {
	if bytes == nil {
		buffer.bytes = nil
	} else {
		buffer.bytes = make([]byte, len(bytes))
		copy(buffer.bytes, bytes)
	}
}

func (buffer *SafeBuffer) maybeFillZero() {
	// Go memory model does not provide any guarantees when this write
	// will be visible, so it's best-effort attempt at safe zeroing.
	for i := range buffer.bytes {
		buffer.bytes[i] = 0
	}
}
