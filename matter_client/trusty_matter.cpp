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

#include "include/trusty_matter.h"
#include "include/matter_ipc.h"

namespace matter {

constexpr size_t kP256_PublicKey_Length = 65;

TrustyMatter::TrustyMatter() {
    int err;
    printf("Connect to Trusty!\n");
    err = trusty_ipc.trusty_matter_connect();
    if (err != 0)
        printf("connecting to ipc error!\n");
}

TrustyMatter::~TrustyMatter() {
    printf("Disconnect from Trusty!\n");
    trusty_ipc.trusty_matter_disconnect();
}

int TrustyMatter::ExportCert(matter_command cmd, uint8_t *out, size_t in_size, size_t &out_size) {
    int rc;
    ExportCertRequest req;
    ExportCertResponse resp;

   rc = trusty_ipc.trusty_matter_send(cmd, req, &resp);
   if (rc != MATTER_ERROR_OK) {
       printf("Trusty:%s: Failed to send request!\n", __func__);
       return MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;
   }

    if (in_size < resp.cert_data.buffer_size()) {
        printf("%s:Out buffer is too small!\n", __func__);
        return MATTER_ERROR_NO_ENOUGH_MEMORY;
    }
    memcpy(out, resp.cert_data.begin(), resp.cert_data.buffer_size());
    out_size = resp.cert_data.buffer_size();

    return MATTER_ERROR_OK;
}

int TrustyMatter::ExportDACCert(uint8_t *out, size_t in_size, size_t &out_size) {
    return ExportCert(MATTER_EXPORT_DAC, out, in_size, out_size);
}

int TrustyMatter::ExportPAICert(uint8_t *out, size_t in_size, size_t &out_size) {
    return ExportCert(MATTER_EXPORT_PAI, out, in_size, out_size);
}

int TrustyMatter::ExportCDCert(uint8_t *out, size_t in_size, size_t &out_size) {
    return ExportCert(MATTER_EXPORT_CD, out, in_size, out_size);
}

int TrustyMatter::SignWithDACKey(const uint8_t *msg, size_t msg_size,
                                 uint8_t *sig, size_t sig_buf_size, size_t &sig_size) {
    int rc = 0;
    SignWithDAKeyRequest req;
    SignWithDAKeyResponse resp;

    req.msg.Reinitialize(msg, msg_size);
    rc = trusty_ipc.trusty_matter_send(MATTER_SIGN_WITH_DAC_KEY, req, &resp);
    if (rc != MATTER_ERROR_OK) {
        printf("%s: Failed to send request!\n", __func__);
        return MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;
    }

    if (sig_buf_size < resp.sig.buffer_size()) {
        printf("%s: out buffer is not enough!\n", __func__);
        return MATTER_ERROR_NO_ENOUGH_MEMORY;
    }

    memcpy(sig, resp.sig.begin(), resp.sig.buffer_size());
    sig_size = resp.sig.buffer_size();

    return MATTER_ERROR_OK;
}

int TrustyMatter::P256KeypairInitialize(uint64_t &p256_handler, uint8_t *pubkey) {
    P256KPInitializeRequest req;
    P256KPInitializeResponse resp;
    int rc = 0;

    req.p256_handler = p256_handler;
    rc = trusty_ipc.trusty_matter_send(MATTER_P256_KEYPAIR_INITIALIZE, req, &resp);
    if (rc != MATTER_ERROR_OK) {
        printf("%s: Failed to send request!\n", __func__);
        return MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;
   }

    if (resp.p256_handler == 0) {
        printf("%s: Invalid p256 handler returned!\n", __func__);
        return MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;
    } else
        p256_handler = resp.p256_handler;

    memcpy(pubkey, resp.public_key.begin(), resp.public_key.buffer_size());
    return MATTER_ERROR_OK;
}

int TrustyMatter::P256KeypairSerialize(const uint64_t &p256_handler, uint8_t *prikey) {
    P256KPSerializeRequest req;
    P256KPSerializeResponse resp;
    int rc = 0;

    req.p256_handler = p256_handler;
    rc = trusty_ipc.trusty_matter_send(MATTER_P256_KEYPAIR_SERIALIZE, req, &resp);
    if (rc != MATTER_ERROR_OK) {
        printf("%s: Failed to send request!\n", __func__);
        return MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;
   }

    memcpy(prikey, resp.private_key.begin(), resp.private_key.buffer_size());
    return MATTER_ERROR_OK;
}

int TrustyMatter::P256KeypairDeserialize(uint64_t &p256_handler, uint8_t *pubkey, size_t pubkey_size, uint8_t *prikey, size_t prikey_size) {
    P256KPDeserializeRequest req;
    P256KPDeserializeResponse resp;
    int rc = 0;

    // store the public and private keys
    req.p256_handler = p256_handler;
    req.public_key.Reinitialize(pubkey, pubkey_size);
    req.private_key.Reinitialize(prikey, prikey_size);

    // IPC call
    rc = trusty_ipc.trusty_matter_send(MATTER_P256_KEYPAIR_DESERIALIZE, req, &resp);
    if (rc != MATTER_ERROR_OK) {
        printf("%s: Failed to send request!\n", __func__);
        return MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;
   }

    // update valid p256_handler
    if (resp.p256_handler == 0) {
        printf("%s: Invalid p256 handler returned!\n", __func__);
        return MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;
    } else
        p256_handler = resp.p256_handler;

    return MATTER_ERROR_OK;
}

int TrustyMatter::P256KeypairECSignMsg(const uint64_t &p256_handler, uint8_t *hash256,
                                       size_t hash256_size, uint8_t *sig, size_t &sig_size) {
    P256KPECSignMsgRequest req;
    P256KPECSignMsgResponse resp;
    int rc = 0;

    req.p256_handler = p256_handler;
    req.hash256.Reinitialize(hash256, hash256_size);

    rc = trusty_ipc.trusty_matter_send(MATTER_P256_KEYPAIR_ECSIGNMSG, req, &resp);
    if (rc != MATTER_ERROR_OK) {
        printf("%s: Failed to send request!\n", __func__);
        return MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;
    }

    memcpy(sig, resp.sig.begin(), resp.sig.buffer_size());
    sig_size = resp.sig.buffer_size();
    return MATTER_ERROR_OK;
}

int TrustyMatter::P256KeypairNewCSR(const uint64_t &p256_handler, uint8_t *out_csr, size_t &csr_length) {
    P256KPNewCSRRequest req;
    P256KPNewCSRResponse resp;
    int rc = 0;

    req.p256_handler = p256_handler;

    rc = trusty_ipc.trusty_matter_send(MATTER_P256_KEYPAIR_NEWCSR, req, &resp);
    if (rc != MATTER_ERROR_OK) {
        printf("%s: Failed to send request!\n", __func__);
        return MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;
    }

    memcpy(out_csr, resp.csr.begin(), resp.csr.buffer_size());
    csr_length = resp.csr.buffer_size();
    return MATTER_ERROR_OK;
}

int TrustyMatter::P256KeypairDestory(uint64_t &p256_handler) {
    int rc = 0;
    P256KPDestoryRequest req;
    P256KPDestoryResponse resp;

    req.p256_handler = p256_handler;

    rc = trusty_ipc.trusty_matter_send(MATTER_P256_KEYPAIR_DESTORY, req, &resp);
    if (rc != MATTER_ERROR_OK) {
        printf("%s: Failed to send request!\n", __func__);
        return MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;
    }

    return MATTER_ERROR_OK;
}

int TrustyMatter::P256KeypairECDH_derive_secret(const uint64_t &p256_handler, const uint8_t *remote_pubkey,
                                                size_t remote_pubkey_length, uint8_t *secret, size_t &secret_length) {
    int rc = 0;
    P256KPECDHDeriveSecretRequest req;
    P256KPECDHDeriveSecretResponse resp;

    if ((remote_pubkey == nullptr) || (remote_pubkey_length != kP256_PublicKey_Length)) {
        printf("%s: wrong remote public key!\n", __func__);
        return MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;
    }

    req.p256_handler = p256_handler;
    req.remote_pubkey.Reinitialize(remote_pubkey, remote_pubkey_length);

    // IPC call
    rc = trusty_ipc.trusty_matter_send(MATTER_P256_KEYPAIR_ECDH_DERIVE_SECRET, req, &resp);
    if (rc != MATTER_ERROR_OK) {
         printf("%s: Failed to send request!\n", __func__);
         return MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;
    }

    memcpy(secret, resp.secret.begin(), resp.secret.buffer_size());
    secret_length = resp.secret.buffer_size();
    return MATTER_ERROR_OK;
}

} //namespace matter
