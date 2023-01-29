/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#include <algorithm>
#include <variant>
#include <vector>

#include <trusty/tipc.h>
#include "include/matter_ipc.h"
#include "include/trusty_matter_ipc.h"
#include "include/Timers.h"

#define TRUSTY_DEVICE_NAME "/dev/trusty-ipc-dev0"
#define MATTER_PORT "com.android.trusty.matter"

namespace matter {

static const int timeout_ms = 10 * 1000;
static const int max_timeout_ms = 60 * 1000;
static const uint32_t TRUSTY_MATTER_RECV_BUF_SIZE = 2 * 4096;
static const uint32_t TRUSTY_MATTER_SEND_BUF_SIZE = \
                       (4096 - sizeof(struct matter_message) - 16 /* tipc header */);

class VectorEraser {
  public:
    VectorEraser(std::vector<uint8_t>* v) : _v(v) {}
    ~VectorEraser() {
        if (_v) {
            std::fill(const_cast<volatile uint8_t*>(_v->data()),
                      const_cast<volatile uint8_t*>(_v->data() + _v->size()), 0);
        }
    }
    void disarm() { _v = nullptr; }
    VectorEraser(const VectorEraser&) = delete;
    VectorEraser& operator=(const VectorEraser&) = delete;
    VectorEraser(VectorEraser&& other) = delete;
    VectorEraser& operator=(VectorEraser&&) = delete;

  private:
    std::vector<uint8_t>* _v;
};

// get system monotonic time
static nsecs_t systemTime() {
    timespec t = {};
    clock_gettime(CLOCK_MONOTONIC, &t);
    return nsecs_t(t.tv_sec)*1000000000LL + t.tv_nsec;
}

int TrustyMatterIPC::trusty_matter_connect() {
    int rc = tipc_connect(TRUSTY_DEVICE_NAME, MATTER_PORT);
    if (rc < 0) {
        return rc;
    }

    handle_ = rc;
    return 0;
}

std::variant<int, std::vector<uint8_t>> TrustyMatterIPC::trusty_matter_call_2(uint32_t cmd, void* in,
                                                                              uint32_t in_size) {
    if (handle_ < 0) {
        printf("trusty: TIPC not connected\n");
        return -EINVAL;
    }

    size_t msg_size = in_size + sizeof(struct matter_message);
    struct matter_message* msg = reinterpret_cast<struct matter_message*>(malloc(msg_size));
    if (!msg) {
        printf("trusty: failed to allocate msg buffer\n");
        return -EINVAL;
    }

    msg->cmd = cmd;
    memcpy(msg->payload, in, in_size);

    nsecs_t start_time_ns = systemTime();
    bool timed_out = false;
    int poll_timeout_ms = timeout_ms;
    while (true) {
        struct pollfd pfd;
        pfd.fd = handle_;
        pfd.events = POLLOUT;
        pfd.revents = 0;

        int p = poll(&pfd, 1, poll_timeout_ms);
        if (p == 0) {
            printf("trusty: write for cmd %d is taking more than %lld nsecs", cmd,
                  (long long)(systemTime() - start_time_ns));
            timed_out = true;
            poll_timeout_ms *= 2;
            if (poll_timeout_ms > max_timeout_ms) {
                poll_timeout_ms = max_timeout_ms;
            }
            continue;
        } else if (p < 0) {
            printf("trusty: write poll error: %d", errno);
        } else if (pfd.revents != POLLOUT) {
            printf("trusty: unexpected poll() result: %d", pfd.revents);
        }
        break;
    }

    ssize_t rc = write(handle_, msg, msg_size);
    if (timed_out) {
        printf("trusty: write for cmd %d finished after %lld nsecs", cmd,
              (long long)(systemTime() - start_time_ns));
    }
    free(msg);

    if (rc < 0) {
        printf("trusty: failed to send cmd (%d) to %s: %s\n", cmd, MATTER_PORT, strerror(errno));
        return -errno;
    }

    std::vector<uint8_t> out(TRUSTY_MATTER_RECV_BUF_SIZE);
    VectorEraser out_eraser(&out);
    uint8_t* write_pos = out.data();
    uint8_t* out_end = out.data() + out.size();

    struct iovec iov[2];
    struct matter_message header;
    iov[0] = {.iov_base = &header, .iov_len = sizeof(struct matter_message)};
    while (true) {
        if (out_end - write_pos < MATTER_MAX_MSG_SIZE) {
            // In stead of using std::vector.resize(), allocate a new one to have chance
            // at zeroing the old buffer.
            std::vector<uint8_t> new_out(out.size() + MATTER_MAX_MSG_SIZE);
            // After the swap below this erases the old out buffer.
            VectorEraser new_out_eraser(&new_out);
            std::copy(out.data(), write_pos, new_out.begin());

            auto write_offset = write_pos - out.data();

            std::swap(new_out, out);

            write_pos = out.data() + write_offset;
            out_end = out.data() + out.size();
        }
        size_t buffer_size = 0;
        if (__builtin_sub_overflow(reinterpret_cast<uintptr_t>(out_end),
                                   reinterpret_cast<uintptr_t>(write_pos), &buffer_size)) {
            return -EOVERFLOW;
        }
        iov[1] = {.iov_base = write_pos, .iov_len = buffer_size};
        start_time_ns = systemTime();
        timed_out = false;
        poll_timeout_ms = timeout_ms;
        while (true) {
            struct pollfd pfd;
            pfd.fd = handle_;
            pfd.events = POLLIN;
            pfd.revents = 0;

            int p = poll(&pfd, 1, poll_timeout_ms);
            if (p == 0) {
                printf("trusty: readv for cmd %d is taking more than %lld nsecs", cmd,
                      (long long)(systemTime() - start_time_ns));
                timed_out = true;
                poll_timeout_ms *= 2;
                if (poll_timeout_ms > max_timeout_ms) {
                    poll_timeout_ms = max_timeout_ms;
                }
                continue;
            } else if (p < 0) {
                printf("trusty: read poll error: %d", errno);
            } else if (pfd.revents != POLLIN) {
                printf("trusty: unexpected poll() result: %d", pfd.revents);
            }
            break;
        }
        rc = readv(handle_, iov, 2);
        if (timed_out) {
            printf("trusty: readv for cmd %d finished after %lld nsecs", cmd,
                  (long long)(systemTime() - start_time_ns));
        }
        if (rc < 0) {
            printf("trusty: failed to retrieve response for cmd (%d) to %s: %s\n", cmd, MATTER_PORT,
                  strerror(errno));
            return -errno;
        }

        if ((size_t)rc < sizeof(struct matter_message)) {
            printf("trusty: invalid response size (%d)\n", (int)rc);
            return -EINVAL;
        }

        if ((cmd | MATTER_RESP_BIT) != (header.cmd & ~(MATTER_STOP_BIT))) {
            printf("trusty: invalid command (%d)", header.cmd);
            return -EINVAL;
        }
        write_pos += ((size_t)rc - sizeof(struct matter_message));
        if (header.cmd & MATTER_STOP_BIT) {
            break;
        }
    }

    out.resize(write_pos - out.data());
    out_eraser.disarm();
    return out;
}

void TrustyMatterIPC::trusty_matter_disconnect() {
    if (handle_ >= 0) {
        tipc_close(handle_);
    }
    handle_ = -1;
}

matter_error_t translate_error(int err) {
    switch (err) {
        case 0:
            return MATTER_ERROR_OK;
        case -EPERM:
        case -EACCES:
            return MATTER_ERROR_SECURE_HW_ACCESS_DENIED;

        case -ECANCELED:
            return MATTER_ERROR_OPERATION_CANCELLED;

        case -ENODEV:
            return MATTER_ERROR_UNIMPLEMENTED;

        case -ENOMEM:
            return MATTER_ERROR_MEMORY_ALLOCATION_FAILED;

        case -EBUSY:
            return MATTER_ERROR_SECURE_HW_BUSY;

        case -EIO:
            return MATTER_ERROR_SECURE_HW_COMMUNICATION_FAILED;

        case -EOVERFLOW:
            return MATTER_ERROR_INVALID_INPUT_LENGTH;

        default:
            return MATTER_ERROR_UNKNOWN_ERROR;
    }
}

matter_error_t TrustyMatterIPC::trusty_matter_send(uint32_t command, const matter::Serializable& req,
                                        matter::MatterResponse* rsp) {
    uint32_t req_size = req.SerializedSize();
    if (req_size > TRUSTY_MATTER_SEND_BUF_SIZE) {
        printf("trusty: Request too big: %u Max size: %u", req_size, TRUSTY_MATTER_SEND_BUF_SIZE);
        return MATTER_ERROR_INVALID_INPUT_LENGTH;
    }

    uint8_t send_buf[TRUSTY_MATTER_SEND_BUF_SIZE];
    matter::Eraser send_buf_eraser(send_buf, TRUSTY_MATTER_SEND_BUF_SIZE);
    req.Serialize(send_buf, send_buf + req_size);

    // Send it
    auto response = trusty_matter_call_2(command, send_buf, req_size);
    if (auto response_buffer = std::get_if<std::vector<uint8_t>>(&response)) {
        matter::Eraser response_buffer_erasor(response_buffer->data(), response_buffer->size());
        printf("trusty: Received %zu byte response\n", response_buffer->size());

        const uint8_t* p = response_buffer->data();
        if (!rsp->Deserialize(&p, p + response_buffer->size())) {
            printf("trusty: Error deserializing response of size %zu\n", response_buffer->size());
            return MATTER_ERROR_UNKNOWN_ERROR;
        } else if (rsp->error != MATTER_ERROR_OK) {
            printf("trusty: Response of size %zu contained error code %d\n", response_buffer->size(),
                  (int)rsp->error);
        }
        return rsp->error;
    } else {
        auto rc = std::get<int>(response);
        // Reset the connection on tipc error
        trusty_matter_disconnect();
        trusty_matter_connect();
        printf("trusty: tipc error: %d\n", rc);
        return translate_error(rc);
    }
}
} // namespace matter
