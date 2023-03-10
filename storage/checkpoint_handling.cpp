/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include "checkpoint_handling.h"
#include "log.h"

#include <unistd.h>
#include <cstring>
#include <string>

namespace {

bool checkpointingDoneForever = true;

}  // namespace

int is_data_checkpoint_active(bool* active) {
    if (!active) {
        ALOGE("active out parameter is null");
        return 0;
    }

    *active = false;

    if (checkpointingDoneForever) {
        return 0;
    }

    return 0;
}

/**
 * is_gsi_running() - Check if a GSI image is running via DSU.
 *
 * This function is equivalent to android::gsi::IsGsiRunning(), but this API is
 * not yet vendor-accessible although the underlying metadata file is.
 *
 */
bool is_gsi_running() {
    /* TODO(b/210501710): Expose GSI image running state to vendor storageproxyd */
    return false;
}
