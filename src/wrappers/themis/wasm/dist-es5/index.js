// Copyright (c) 2019 Cossack Labs Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * @file
 * WasmThemis module entry point.
 */

const context = require('./context.js')
const libthemis = require('./libthemis.js')

Object.assign(module.exports
  , require('./secure_cell.js')
  , require('./secure_comparator.js')
  , require('./secure_keygen.js')
  , require('./secure_message.js')
  , require('./secure_session.js')
  , require('./themis_error.js')
)

async function initialize(wasmPath) {
    let exports = await libthemis({
        onRuntimeInitialized: function () {},
        locateFile: wasmPath ? function () {
            return wasmPath;
        } : undefined,
    })
    // Fill in WasmThemis "native" WebAssembly exports
    Object.assign(context, exports)
    return module.exports
}

module.exports.initialize = initialize
