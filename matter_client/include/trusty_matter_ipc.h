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

#include <variant>
#include "matter_defs.h"
#include "serializable.h"
#include "matter_messages.h"

namespace matter {
class TrustyMatterIPC {
public:
    TrustyMatterIPC():handle_(-1) {};

    int trusty_matter_connect();
    void trusty_matter_disconnect();
    matter_error_t trusty_matter_send(uint32_t command, const matter::Serializable& req,
                                      matter::MatterResponse* rsp);
private:
    int handle_ = -1;
    std::variant<int, std::vector<uint8_t>> trusty_matter_call_2(uint32_t cmd, void* in, uint32_t in_size);
};
} // namespace matter
