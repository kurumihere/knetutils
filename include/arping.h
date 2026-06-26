/***************************************************************************
 * arping.h -- Header definitions for the arping utility                   *
 *                                                                         *
 ***********************IMPORTANT KNETUTILS LICENSE TERMS******************* *
 *                                                                         *
 * knetutils is (C) 2026 kurumihere                                        *
 *                                                                         *
 * Redistribution and use in source and binary forms, with or without      *
 * modification, are permitted provided that the following conditions are  *
 * met:                                                                    *
 *                                                                         *
 * 1. Redistributions of source code must retain the above copyright       *
 *    notice, this list of conditions and the following disclaimer.        *
 *                                                                         *
 * 2. Redistributions in binary form must reproduce the above copyright    *
 *    notice, this list of conditions and the following disclaimer in the  *
 *    documentation and/or other materials provided with the distribution. *
 *                                                                         *
 * 3. Neither the name of the copyright holder nor the names of its        *
 *    contributors may be used to endorse or promote products derived from *
 *    this software without specific prior written permission.             *
 *                                                                         *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS     *
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT       *
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A *
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT      *
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,  *
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT        *
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,   *
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY   *
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT     *
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE   *
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.    *
 *                                                                         *
 ***************************************************************************/

#ifndef KNETUTILS_ARPING_H
#define KNETUTILS_ARPING_H

#include <net/ethernet.h>
#include <stdbool.h>
#include <sys/types.h>

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

typedef struct {
        const char *iface;
        u_int target_ip;
        u_int source_ip;
        u_char source_mac[ETH_ALEN];
        u_int count;
        u_int64_t timeout_ns;
        u_int64_t interval_ns;
        bool quiet;
        bool unsolicited;
        bool dad;
        bool gateway;
        bool cisco_style;
        bool quit_on_reply;
        bool use_reply;
        bool keep_broadcast;
        const char *time_unit;
} arping_config_t;

int arping_run(const arping_config_t *config);

#endif
