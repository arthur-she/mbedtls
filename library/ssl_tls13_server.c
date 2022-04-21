/*
 *  TLS 1.3 server-side functions
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
*/

#include "common.h"

#if defined(MBEDTLS_SSL_SRV_C) && defined(MBEDTLS_SSL_PROTO_TLS1_3)

#include "mbedtls/debug.h"
#include "mbedtls/error.h"
#include "mbedtls/platform.h"
#include <string.h>

#include "ssl_misc.h"
#include "ssl_debug_helpers.h"
#include "ssl_tls13_keys.h"

static int ssl_tls13_prepare_encrypted_extensions( mbedtls_ssl_context *ssl )
{
    int ret ;
    mbedtls_ssl_key_set traffic_keys;
    mbedtls_ssl_transform *transform_handshake = NULL;

    /* Compute handshake secret */
    ret = mbedtls_ssl_tls13_key_schedule_stage_handshake( ssl );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls13_key_schedule_stage_handshake", ret );
        return( ret );
    }

    /* Derive handshake key material */
    ret = mbedtls_ssl_tls13_generate_handshake_keys( ssl, &traffic_keys );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1,
                "mbedtls_ssl_tls13_generate_handshake_keys", ret );
        return( ret );
    }

    transform_handshake = mbedtls_calloc( 1, sizeof( mbedtls_ssl_transform ) );
    if( transform_handshake == NULL )
        return( MBEDTLS_ERR_SSL_ALLOC_FAILED );

    /* Setup transform from handshake key material */
    ret = mbedtls_ssl_tls13_populate_transform(
                               transform_handshake,
                               ssl->conf->endpoint,
                               ssl->session_negotiate->ciphersuite,
                               &traffic_keys,
                               ssl );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls13_populate_transform", ret );
        mbedtls_free( transform_handshake );
        return( ret );
    }

    ssl->handshake->transform_handshake = transform_handshake;
    mbedtls_ssl_set_outbound_transform( ssl, ssl->handshake->transform_handshake );

    /*
     * Switch to our negotiated transform and session parameters for outbound
     * data.
     */
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "switching to new transform spec for outbound data" ) );
    memset( ssl->out_ctr, 0, 8 );

    return( 0 );
}

/*
 * struct {
 *    Extension extensions<0..2 ^ 16 - 1>;
 * } EncryptedExtensions;
 *
 */
static int ssl_tls13_write_encrypted_extensions( mbedtls_ssl_context *ssl,
                                                 unsigned char *buf,
                                                 unsigned char *end,
                                                 size_t *out_len )
{
    ((void) ssl);
    ((void) buf);
    ((void) end);
    *out_len = 0;

    /* In the first pass, we focus on pure ephemeral key exchanges,
     * excluding PSK and (thus) 0-RTT.
     *
     * TODO: write encrypted extensions
     */

    return( 0 );
}

static int ssl_tls13_process_encrypted_extensions( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *buf;
    size_t buf_len = 0;
    size_t msg_len = 0;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write encrypted extension" ) );

    if( ssl->handshake->state_local.encrypted_extensions_out.preparation_done == 0 )
    {
        MBEDTLS_SSL_PROC_CHK( ssl_tls13_prepare_encrypted_extensions( ssl ) );
        ssl->handshake->state_local.encrypted_extensions_out.preparation_done = 1;
    }

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_tls13_start_handshake_msg( ssl,
                       MBEDTLS_SSL_HS_ENCRYPTED_EXTENSIONS, &buf, &buf_len ) );

    MBEDTLS_SSL_PROC_CHK( ssl_tls13_write_encrypted_extensions(
                              ssl, buf, buf + buf_len, &msg_len ) );

    mbedtls_ssl_tls13_add_hs_msg_to_checksum(
        ssl, MBEDTLS_SSL_HS_ENCRYPTED_EXTENSIONS, buf, msg_len );

    /* Update state */
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CERTIFICATE_REQUEST );

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_tls13_finish_handshake_msg(
                              ssl, buf_len, msg_len ) );

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write encrypted extension" ) );
    return( ret );
}


int mbedtls_ssl_tls13_handshake_server_step( mbedtls_ssl_context *ssl )
{
    int ret = 0;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "tls13 server state: %s(%d)",
                                mbedtls_ssl_states_str( ssl->state ),
                                ssl->state ) );
    switch( ssl->state )
    {
        case MBEDTLS_SSL_ENCRYPTED_EXTENSIONS:
            ret = ssl_tls13_process_encrypted_extensions( ssl );
            break;

        default:
            return( MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE );
    }

    return( ret );
}

#endif /* MBEDTLS_SSL_SRV_C && MBEDTLS_SSL_PROTO_TLS1_3 */
