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

import (
	"unsafe"
)

// SafeBuffer wraps a byte slice and provides safe access to its raw memory.
//
// Since Go 1.12 SafeBuffer is zero-cost.
// In Go 1.11 and earlier SafeBuffer makes a copy of the byte slice.
// You should call Close() to zero a possible copy made by SafeBuffer.
type SafeBuffer struct {
	bytes []byte
}

// WrapBuffer wraps a byte slice into a SafeBuffer.
func WrapBuffer(bytes []byte) SafeBuffer {
	var buffer SafeBuffer
	buffer.maybeCopy(bytes)
	return buffer
}

// Take returns the wrapped byte slice back.
func (buffer *SafeBuffer) Take() []byte {
	bytes := buffer.bytes
	buffer.bytes = nil
	return bytes
}

// Close makes SafeBuffer unusable anymore.
func (buffer *SafeBuffer) Close() {
	buffer.maybeFillZero()
	buffer.bytes = nil
}

// Pointer returns a pointer to beginning of the buffer.
func (buffer *SafeBuffer) Pointer() unsafe.Pointer {
	if buffer.bytes == nil {
		return nil
	}
	return unsafe.Pointer(&buffer.bytes[0])
}

// Length returns length of the buffer in bytes.
func (buffer *SafeBuffer) Length() int {
	// We would like to return C.size_t here, but C import is different for each package
	// so you'll have to cast it manually at use site. Sorry.
	return len(buffer.bytes)
}
