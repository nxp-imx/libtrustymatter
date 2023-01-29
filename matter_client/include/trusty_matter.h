/*
 * Copyright 2014 The Android Open Source Project
 *
 * Copyright 2023 NXP
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include "trusty_matter_ipc.h"
#include "matter_ipc.h"

namespace matter {

class TrustyMatter {
public:
    ~TrustyMatter();
    TrustyMatter();

    int ExportDACCert(uint8_t *out, size_t in_size, size_t &out_size);
    int ExportPAICert(uint8_t *out, size_t in_size, size_t &out_size);
    int ExportCDCert(uint8_t *out, size_t in_size, size_t &out_size);
    int SignWithDACKey(const uint8_t *msg, size_t msg_size,
                       uint8_t *sig, size_t sig_buf_size, size_t &sig_size);
    int P256KeypairInitialize(uint64_t &p256_handler, uint8_t *pubkey);
    int P256KeypairSerialize(const uint64_t &p256_handler, uint8_t *prikey);
    int P256KeypairDeserialize(uint64_t &p256_handler, uint8_t *pubkey, size_t pubkey_size, uint8_t *prikey, size_t prikey_size);
    int P256KeypairDestory(uint64_t &p256_handler);
    int P256KeypairECSignMsg(const uint64_t &p256_handler, uint8_t *hash256, size_t hash256_size, uint8_t *sig, size_t &sig_size);
    int P256KeypairNewCSR(const uint64_t &p256_handler, uint8_t *out_csr, size_t &csr_length);
    int P256KeypairECDH_derive_secret(const uint64_t &p256_handler, const uint8_t *remote_pubkey,
                                      size_t remote_pubkey_length, uint8_t *secret, size_t &secret_length);

private:
    int ExportCert(matter_command cmd, uint8_t *out, size_t in_size, size_t &out_size);
    TrustyMatterIPC trusty_ipc;
};

} // namespace matter
