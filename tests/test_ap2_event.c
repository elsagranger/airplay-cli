#include <assert.h>
#include <math.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>

#include "ap2_mrp.h"
#include "ap2_plist.h"
#include "cross_log.h"

#define KEY_SIZE 32
#define TAG_SIZE 16

struct command_capture {
    ap2_remote_command_t commands[16];
    int count;
};

static log_level test_log_level = lSILENCE;
log_level *loglevel = &test_log_level;

static void capture_remote_command(
    ap2_remote_command_t command, void *userdata)
{
    struct command_capture *capture = userdata;
    assert(capture && capture->count < 16);
    capture->commands[capture->count++] = command;
}

static void derive_key_from(const uint8_t *secret, size_t secret_len,
                            const char *info, uint8_t key[KEY_SIZE])
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    size_t len = KEY_SIZE;
    assert(ctx);
    assert(EVP_PKEY_derive_init(ctx) > 0);
    assert(EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha512()) > 0);
    assert(EVP_PKEY_CTX_set1_hkdf_salt(
               ctx, (const unsigned char *)"Events-Salt", 11) > 0);
    assert(EVP_PKEY_CTX_set1_hkdf_key(ctx, secret, (int)secret_len) > 0);
    assert(EVP_PKEY_CTX_add1_hkdf_info(
               ctx, (const unsigned char *)info, strlen(info)) > 0);
    assert(EVP_PKEY_derive(ctx, key, &len) > 0);
    EVP_PKEY_CTX_free(ctx);
}

static void derive_key(const uint8_t secret[KEY_SIZE], const char *info,
                       uint8_t key[KEY_SIZE])
{
    derive_key_from(secret, KEY_SIZE, info, key);
}

static void make_nonce(uint64_t counter, uint8_t nonce[12])
{
    memset(nonce, 0, 12);
    for (int i = 0; i < 8; i++)
        nonce[4 + i] = (uint8_t)(counter >> (i * 8));
}

static int encrypt_frame(const uint8_t key[KEY_SIZE], uint64_t counter,
                         const uint8_t *plain, int plain_len, uint8_t *frame)
{
    uint8_t aad[2] = {plain_len & 0xff, (plain_len >> 8) & 0xff};
    uint8_t nonce[12];
    make_nonce(counter, nonce);
    memcpy(frame, aad, 2);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, total = 0;
    assert(ctx);
    assert(EVP_EncryptInit_ex(
               ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) > 0);
    assert(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) > 0);
    assert(EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) > 0);
    assert(EVP_EncryptUpdate(ctx, NULL, &len, aad, 2) > 0);
    assert(EVP_EncryptUpdate(
               ctx, frame + 2, &len, plain, plain_len) > 0);
    total = len;
    assert(EVP_EncryptFinal_ex(ctx, frame + 2 + total, &len) > 0);
    total += len;
    assert(EVP_CIPHER_CTX_ctrl(
               ctx, EVP_CTRL_AEAD_GET_TAG, TAG_SIZE,
               frame + 2 + total) > 0);
    EVP_CIPHER_CTX_free(ctx);
    return total + 2 + TAG_SIZE;
}

static int decrypt_frame(const uint8_t key[KEY_SIZE], uint64_t counter,
                         const uint8_t *frame, int frame_len, uint8_t *plain)
{
    assert(frame_len >= 2 + TAG_SIZE);
    int cipher_len = frame[0] | (frame[1] << 8);
    assert(frame_len == cipher_len + 2 + TAG_SIZE);
    uint8_t nonce[12];
    make_nonce(counter, nonce);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, total = 0;
    assert(ctx);
    assert(EVP_DecryptInit_ex(
               ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) > 0);
    assert(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) > 0);
    assert(EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) > 0);
    assert(EVP_DecryptUpdate(ctx, NULL, &len, frame, 2) > 0);
    assert(EVP_DecryptUpdate(
               ctx, plain, &len, frame + 2, cipher_len) > 0);
    total = len;
    assert(EVP_CIPHER_CTX_ctrl(
               ctx, EVP_CTRL_AEAD_SET_TAG, TAG_SIZE,
               (void *)(frame + 2 + cipher_len)) > 0);
    assert(EVP_DecryptFinal_ex(ctx, plain + total, &len) > 0);
    total += len;
    EVP_CIPHER_CTX_free(ctx);
    return total;
}

static struct ap2_mrp_ctx *create_mrp_with_callback(
    const uint8_t secret[KEY_SIZE], int event_sock,
    ap2_remote_command_cb_t callback, void *userdata)
{
    struct ap2_mrp_ctx *mrp = ap2_mrp_create(
        "127.0.0.1", 7000, NULL, "1A2B3D4EA1B2C3D4",
        "Music Assistant", "11111111-2222-4333-8444-555555555555",
        "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE", secret, KEY_SIZE);
    assert(mrp);
    ap2_mrp_set_remote_command_callback(mrp, callback, userdata);
    assert(ap2_mrp_attach_events(mrp, event_sock));
    assert(ap2_mrp_event_status(mrp) == 1);
    return mrp;
}

static struct ap2_mrp_ctx *create_mrp(const uint8_t secret[KEY_SIZE],
                                      int event_sock)
{
    return create_mrp_with_callback(secret, event_sock, NULL, NULL);
}

static int build_event_request(uint8_t *encrypted, size_t encrypted_size,
                               const uint8_t key[KEY_SIZE],
                               uint64_t counter, int cseq,
                               const uint8_t *body, int body_len)
{
    uint8_t request[1024];
    int header_len = snprintf(
        (char *)request, sizeof(request),
        "POST /command RTSP/1.0\r\n"
        "CSeq: %d\r\n"
        "Server: AirTunes/1.0\r\n"
        "Content-Type: application/x-apple-binary-plist\r\n"
        "Content-Length: %d\r\n\r\n",
        cseq, body_len);
    assert(header_len > 0 && header_len + body_len < (int)sizeof(request));
    memcpy(request + header_len, body, (size_t)body_len);

    int request_len = header_len + body_len;
    assert((size_t)(request_len + 2 + TAG_SIZE) <= encrypted_size);
    return encrypt_frame(
        key, counter, request, request_len, encrypted);
}

static int build_typed_command_request(
    uint8_t *encrypted, size_t encrypted_size,
    const uint8_t key[KEY_SIZE], uint64_t counter, int cseq,
    const char *type, const char *value)
{
    ap2_pl_node *root = ap2_pl_dict();
    ap2_pl_dict_set(root, "type", ap2_pl_string(type));
    ap2_pl_dict_set(root, "value", ap2_pl_string(value));
    uint8_t *body = NULL;
    int body_len = ap2_pl_serialize(root, &body);
    ap2_pl_free(root);
    assert(body_len > 0 && body);
    int encrypted_len = build_event_request(
        encrypted, encrypted_size, key, counter, cseq, body, body_len);
    free(body);
    return encrypted_len;
}

static int build_command_request(uint8_t *encrypted, size_t encrypted_size,
                                 const uint8_t key[KEY_SIZE],
                                 uint64_t counter, int cseq,
                                 const char *value)
{
    return build_typed_command_request(
        encrypted, encrypted_size, key, counter, cseq,
        "sendMediaRemoteCommand", value);
}

static int build_embedded_nul_request(
    uint8_t *encrypted, size_t encrypted_size,
    const uint8_t key[KEY_SIZE], uint64_t counter, int cseq)
{
    ap2_pl_node *root = ap2_pl_dict();
    ap2_pl_dict_set(root, "type",
                    ap2_pl_string("sendMediaRemoteCommand"));
    ap2_pl_dict_set(root, "value", ap2_pl_string("playXjunk"));
    uint8_t *body = NULL;
    int body_len = ap2_pl_serialize(root, &body);
    ap2_pl_free(root);
    assert(body_len > 0 && body);

    bool replaced = false;
    for (int i = 0; i + 9 <= body_len; i++) {
        if (memcmp(body + i, "playXjunk", 9) == 0) {
            body[i + 4] = '\0';
            replaced = true;
            break;
        }
    }
    assert(replaced);
    int encrypted_len = build_event_request(
        encrypted, encrypted_size, key, counter, cseq, body, body_len);
    free(body);
    return encrypted_len;
}

static int build_nested_command_request(
    uint8_t *encrypted, size_t encrypted_size,
    const uint8_t key[KEY_SIZE], uint64_t counter, int cseq)
{
    ap2_pl_node *nested = ap2_pl_dict();
    ap2_pl_dict_set(nested, "type",
                    ap2_pl_string("sendMediaRemoteCommand"));
    ap2_pl_dict_set(nested, "value", ap2_pl_string("play"));
    ap2_pl_node *root = ap2_pl_dict();
    ap2_pl_dict_set(root, "payload", nested);
    uint8_t *body = NULL;
    int body_len = ap2_pl_serialize(root, &body);
    ap2_pl_free(root);
    assert(body_len > 0 && body);
    int encrypted_len = build_event_request(
        encrypted, encrypted_size, key, counter, cseq, body, body_len);
    free(body);
    return encrypted_len;
}

static void send_request(int fd, const uint8_t key[KEY_SIZE],
                         uint64_t counter, int cseq, const char *value)
{
    uint8_t encrypted[1200];
    int encrypted_len = build_command_request(
        encrypted, sizeof(encrypted), key, counter, cseq, value);
    assert(write(fd, encrypted, (size_t)encrypted_len) == encrypted_len);
}

static void read_response(int fd, const uint8_t key[KEY_SIZE],
                          uint64_t counter, int cseq)
{
    uint8_t response_frame[2048], response[2048];
    assert(recv(fd, response_frame, 2, MSG_WAITALL) == 2);
    int cipher_len = response_frame[0] | (response_frame[1] << 8);
    int remaining = cipher_len + TAG_SIZE;
    assert(recv(fd, response_frame + 2, (size_t)remaining, MSG_WAITALL) ==
           remaining);
    int response_len = decrypt_frame(
        key, counter, response_frame, remaining + 2, response);
    response[response_len] = '\0';
    char expected_cseq[32];
    snprintf(expected_cseq, sizeof(expected_cseq), "CSeq: %d\r\n", cseq);
    assert(strstr((char *)response, "RTSP/1.0 200 OK\r\n"));
    assert(strstr((char *)response, "Content-Length: 0\r\n"));
    assert(strstr((char *)response, "Audio-Latency: 0\r\n"));
    assert(strstr((char *)response, "Server: AirTunes/1.0\r\n"));
    assert(strstr((char *)response, expected_cseq));
}

static bool contains_bytes(const uint8_t *haystack, int haystack_len,
                           const uint8_t *needle, int needle_len)
{
    for (int i = 0; i + needle_len <= haystack_len; i++) {
        if (memcmp(haystack + i, needle, (size_t)needle_len) == 0)
            return true;
    }
    return false;
}

static void test_artwork_snapshot_generation(const uint8_t secret[KEY_SIZE])
{
    static const uint8_t first_art[] =
        {0xff, 0xd8, 0xf1, 0x11, 0x22, 0x33, 0xff, 0xd9};
    static const uint8_t second_art[] =
        {0xff, 0xd8, 0xe2, 0x91, 0x82, 0x73, 0xff, 0xd9};
    struct ap2_mrp_ctx *mrp = ap2_mrp_create(
        "127.0.0.1", 7000, NULL, "1A2B3D4EA1B2C3D4",
        "Music Assistant", "11111111-2222-4333-8444-555555555555",
        "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE", secret, KEY_SIZE);
    assert(mrp);

    assert(ap2_mrp_set_artwork(
        mrp, "image/jpeg", first_art, (int)sizeof(first_art), NULL));
    uint8_t *first_snapshot = NULL;
    int first_len = 0;
    assert(ap2_mrp_build_nowplaying_command(
        mrp, &first_snapshot, &first_len));
    assert(contains_bytes(
        first_snapshot, first_len, first_art, (int)sizeof(first_art)));

    /* Replacement art replaces the staged bytes... */
    assert(ap2_mrp_set_artwork(
        mrp, "image/jpeg", second_art, (int)sizeof(second_art), NULL));
    uint8_t *second_snapshot = NULL;
    int second_len = 0;
    assert(ap2_mrp_build_nowplaying_command(
        mrp, &second_snapshot, &second_len));
    assert(contains_bytes(
        second_snapshot, second_len, second_art, (int)sizeof(second_art)));
    assert(!contains_bytes(
        second_snapshot, second_len, first_art, (int)sizeof(first_art)));

    /* ...and the bytes ride every later snapshot too: the npi-text bridge
     * replaces the receiver's whole now-playing info per push, so a snapshot
     * without the bytes would drop the receiver's artwork. */
    uint8_t *reference_snapshot = NULL;
    int reference_len = 0;
    assert(ap2_mrp_build_nowplaying_command(
        mrp, &reference_snapshot, &reference_len));
    assert(contains_bytes(
        reference_snapshot, reference_len,
        second_art, (int)sizeof(second_art)));

    free(first_snapshot);
    free(second_snapshot);
    free(reference_snapshot);
    ap2_mrp_destroy(mrp);
}

/* Transient pair-setup: the event keys derive from the full 64-byte SRP
 * session key (as owntone's pair_homekit does), of which the audio key is
 * only the 32-byte prefix. Measured on a HomePod (AudioAccessory5,1, HomePod
 * OS 27.0): keyed from that prefix, the first Siri command fails to decrypt
 * and the session is torn down. */
static void test_transient_kdf_secret(void)
{
    enum { SRP_KEY_SIZE = 64 };
    uint8_t session_key[SRP_KEY_SIZE];
    for (int i = 0; i < SRP_KEY_SIZE; i++) session_key[i] = (uint8_t)(0xA0 ^ i);
    uint8_t receiver_key[KEY_SIZE], sender_key[KEY_SIZE];
    derive_key_from(session_key, SRP_KEY_SIZE,
                    "Events-Write-Encryption-Key", receiver_key);
    derive_key_from(session_key, SRP_KEY_SIZE,
                    "Events-Read-Encryption-Key", sender_key);

    int sockets[2];
    struct timeval timeout = {.tv_sec = 2};

    /* Keyed from the full session key: Siri "next" and a top-surface tap
     * decode. */
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    assert(setsockopt(sockets[1], SOL_SOCKET, SO_RCVTIMEO,
                      &timeout, sizeof(timeout)) == 0);
    struct command_capture capture = {0};
    struct ap2_mrp_ctx *mrp = ap2_mrp_create(
        "127.0.0.1", 7000, NULL, "1A2B3D4EA1B2C3D4",
        "Music Assistant", "11111111-2222-4333-8444-555555555555",
        "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE", session_key, SRP_KEY_SIZE);
    assert(mrp);
    ap2_mrp_set_remote_command_callback(mrp, capture_remote_command, &capture);
    assert(ap2_mrp_attach_events(mrp, sockets[0]));
    send_request(sockets[1], receiver_key, 0, 1, "nitm");
    send_request(sockets[1], receiver_key, 1, 2, "paus");
    ap2_mrp_tick(mrp);
    read_response(sockets[1], sender_key, 0, 1);
    read_response(sockets[1], sender_key, 1, 2);
    assert(ap2_mrp_event_status(mrp) == 1);
    assert(capture.count == 2);
    assert(capture.commands[0] == AP2_REMOTE_COMMAND_NEXT);
    assert(capture.commands[1] == AP2_REMOTE_COMMAND_PAUSE);
    ap2_mrp_destroy(mrp);
    close(sockets[1]);

    /* Keyed from the 32-byte audio-key prefix only: the frame does not
     * authenticate, nothing is dispatched and the channel closes. */
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    memset(&capture, 0, sizeof(capture));
    mrp = create_mrp_with_callback(session_key, sockets[0],
                                   capture_remote_command, &capture);
    send_request(sockets[1], receiver_key, 0, 1, "nitm");
    ap2_mrp_tick(mrp);
    assert(ap2_mrp_event_status(mrp) == 0);
    assert(capture.count == 0);
    ap2_mrp_destroy(mrp);
    close(sockets[1]);

    /* An out-of-range secret length is refused at creation. */
    uint8_t oversized[SRP_KEY_SIZE + 1] = {0};
    assert(!ap2_mrp_create(
        "127.0.0.1", 7000, NULL, "1A2B3D4EA1B2C3D4",
        "Music Assistant", "11111111-2222-4333-8444-555555555555",
        "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE", oversized, sizeof(oversized)));
    assert(!ap2_mrp_create(
        "127.0.0.1", 7000, NULL, "1A2B3D4EA1B2C3D4",
        "Music Assistant", "11111111-2222-4333-8444-555555555555",
        "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE", session_key, 0));
}

struct volume_capture {
    int fd;
    const uint8_t *key;
    uint64_t counter;
    int cseq;
    int count;
    double expected;
};

static void capture_remote_volume(double volume, void *userdata)
{
    struct volume_capture *capture = userdata;
    assert(volume == capture->expected);
    /* Consume and authenticate the ACK inside the callback: it must already
     * be on the socket before the application is notified. */
    read_response(capture->fd, capture->key, capture->counter, capture->cseq);
    capture->counter++;
    capture->cseq++;
    capture->count++;
}

enum volume_shape {
    VOLUME_ROOT, VOLUME_PARAMS, VOLUME_PAYLOAD, VOLUME_DEEP_PARAMS,
    VOLUME_BAD_PARAMS, VOLUME_ROOT_OVERRIDES_PARAMS, VOLUME_NESTED_COMMAND
};

static int build_volume_request(
    uint8_t *encrypted, size_t encrypted_size, const uint8_t key[KEY_SIZE],
    uint64_t counter, int cseq, enum volume_shape shape, ap2_pl_node *value)
{
    ap2_pl_node *root = ap2_pl_dict();
    ap2_pl_dict_set(root, "type", ap2_pl_string("sendMediaRemoteCommand"));
    ap2_pl_dict_set(root, "value", ap2_pl_string("dvlc"));
    ap2_pl_node *target = root;
    if (shape == VOLUME_PARAMS || shape == VOLUME_PAYLOAD ||
        shape == VOLUME_DEEP_PARAMS) {
        target = ap2_pl_dict();
        ap2_pl_dict_set(root, shape == VOLUME_PAYLOAD ? "payload" : "params",
                        target);
        if (shape == VOLUME_DEEP_PARAMS) {
            ap2_pl_node *nested = ap2_pl_dict();
            ap2_pl_dict_set(target, "nested", nested);
            target = nested;
        }
    } else if (shape == VOLUME_BAD_PARAMS) {
        ap2_pl_dict_set(root, "params", ap2_pl_string("not a dictionary"));
        ap2_pl_node *unrelated = ap2_pl_dict();
        ap2_pl_dict_set(unrelated, "volume", ap2_pl_real(0.5));
        ap2_pl_dict_set(root, "payload", unrelated);
    } else if (shape == VOLUME_ROOT_OVERRIDES_PARAMS) {
        ap2_pl_node *params = ap2_pl_dict();
        ap2_pl_dict_set(params, "volume", ap2_pl_real(0.5));
        ap2_pl_dict_set(root, "params", params);
    }
    if (value) ap2_pl_dict_set(target, "volume", value);
    if (shape == VOLUME_NESTED_COMMAND) {
        ap2_pl_node *outer = ap2_pl_dict();
        ap2_pl_dict_set(outer, "payload", root);
        root = outer;
    }
    uint8_t *body = NULL;
    int body_len = ap2_pl_serialize(root, &body);
    ap2_pl_free(root);
    assert(body_len > 0 && body);
    int encrypted_len = build_event_request(
        encrypted, encrypted_size, key, counter, cseq, body, body_len);
    free(body);
    return encrypted_len;
}

static void test_volume_events(const uint8_t secret[KEY_SIZE])
{
    uint8_t receiver_key[KEY_SIZE], sender_key[KEY_SIZE];
    derive_key(secret, "Events-Write-Encryption-Key", receiver_key);
    derive_key(secret, "Events-Read-Encryption-Key", sender_key);
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    struct timeval timeout = {.tv_sec = 2};
    assert(setsockopt(sockets[1], SOL_SOCKET, SO_RCVTIMEO,
                      &timeout, sizeof(timeout)) == 0);
    struct command_capture commands = {0};
    struct ap2_mrp_ctx *mrp = create_mrp_with_callback(
        secret, sockets[0], capture_remote_command, &commands);
    struct volume_capture capture = {.fd = sockets[1], .key = sender_key};
    ap2_mrp_set_remote_volume_callback(mrp, capture_remote_volume, &capture);

    enum { NUMBER_REAL, NUMBER_INT, NUMBER_BOOL, NUMBER_STRING, NUMBER_NONE,
           NUMBER_DICT };
    static const struct {
        enum volume_shape shape;
        int kind;
        double value;
        bool valid;
    } cases[] = {
        {VOLUME_ROOT, NUMBER_REAL, 0.375, true},
        {VOLUME_PARAMS, NUMBER_REAL, 0.625, true},
        {VOLUME_ROOT, NUMBER_INT, 0, true},
        {VOLUME_PARAMS, NUMBER_INT, 1, true},
        {VOLUME_ROOT, NUMBER_REAL, 0, true},
        {VOLUME_PARAMS, NUMBER_REAL, 1, true},
        {VOLUME_ROOT, NUMBER_INT, 1, true},
        {VOLUME_PARAMS, NUMBER_INT, 0, true},
        {VOLUME_ROOT, NUMBER_REAL, -0.01, false},
        {VOLUME_PARAMS, NUMBER_REAL, 1.01, false},
        {VOLUME_ROOT, NUMBER_REAL, NAN, false},
        {VOLUME_PARAMS, NUMBER_REAL, INFINITY, false},
        {VOLUME_ROOT, NUMBER_REAL, -INFINITY, false},
        {VOLUME_ROOT, NUMBER_INT, -1, false},
        {VOLUME_PARAMS, NUMBER_INT, 2, false},
        {VOLUME_ROOT, NUMBER_BOOL, 0, false},
        {VOLUME_PARAMS, NUMBER_BOOL, 1, false},
        {VOLUME_ROOT, NUMBER_STRING, 0, false},
        {VOLUME_PARAMS, NUMBER_STRING, 0, false},
        {VOLUME_ROOT, NUMBER_NONE, 0, false},
        {VOLUME_PARAMS, NUMBER_NONE, 0, false},
        {VOLUME_PAYLOAD, NUMBER_REAL, 0.5, false},
        {VOLUME_DEEP_PARAMS, NUMBER_REAL, 0.5, false},
        {VOLUME_BAD_PARAMS, NUMBER_NONE, 0, false},
        {VOLUME_ROOT_OVERRIDES_PARAMS, NUMBER_BOOL, 1, false},
        {VOLUME_ROOT_OVERRIDES_PARAMS, NUMBER_REAL, 0.25, true},
        {VOLUME_ROOT, NUMBER_DICT, 0, false},
        {VOLUME_NESTED_COMMAND, NUMBER_REAL, 0.5, false},
    };
    int expected_count = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        ap2_pl_node *value = NULL;
        switch (cases[i].kind) {
        case NUMBER_REAL: value = ap2_pl_real(cases[i].value); break;
        case NUMBER_INT: value = ap2_pl_int((int64_t)cases[i].value); break;
        case NUMBER_BOOL: value = ap2_pl_bool(cases[i].value != 0); break;
        case NUMBER_STRING: value = ap2_pl_string("0.5"); break;
        case NUMBER_DICT: value = ap2_pl_dict(); break;
        }
        capture.counter = i;
        capture.cseq = 100 + (int)i;
        capture.expected = cases[i].value;
        uint8_t encrypted[1200];
        int len = build_volume_request(
            encrypted, sizeof(encrypted), receiver_key, i, capture.cseq,
            cases[i].shape, value);
        /* Split the length prefix, ciphertext and authentication tag. */
        const int cuts[] = {1, 17, len - 1, len};
        int sent = 0;
        for (size_t part = 0; part < sizeof(cuts) / sizeof(cuts[0]); part++) {
            int bytes = cuts[part] - sent;
            assert(write(sockets[1], encrypted + sent, (size_t)bytes) == bytes);
            sent = cuts[part];
            ap2_mrp_tick(mrp);
            if (sent < len) assert(capture.count == expected_count);
        }
        if (cases[i].valid) expected_count++;
        else read_response(sockets[1], sender_key, i, capture.cseq);
        assert(capture.count == expected_count);
        assert(commands.count == 0);
        assert(ap2_mrp_event_status(mrp) == 1);
    }

    /* Coalesced unknown and transport events after volume traffic must retain
     * ACK nonce progression and explicit play/pause/toggle semantics. */
    uint64_t counter = sizeof(cases) / sizeof(cases[0]);
    const char *names[] = {"unknown", "play", "paus", "plps", "nitm", "pitm"};
    uint8_t batch[7200];
    int batch_len = 0;
    capture.counter = counter;
    capture.cseq = 180;
    capture.expected = 0.75;
    for (int i = 0; i < 2; i++)
        batch_len += build_volume_request(
            batch + batch_len, sizeof(batch) - (size_t)batch_len,
            receiver_key, counter + (uint64_t)i, 180 + i,
            i == 0 ? VOLUME_ROOT : VOLUME_PARAMS, ap2_pl_real(0.75));
    assert(write(sockets[1], batch, (size_t)batch_len) == batch_len);
    ap2_mrp_tick(mrp);
    expected_count += 2;
    assert(capture.count == expected_count);
    assert(commands.count == 0);
    counter += 2;
    batch_len = 0;
    for (int i = 0; i < 6; i++)
        batch_len += build_command_request(
            batch + batch_len, sizeof(batch) - (size_t)batch_len,
            receiver_key, counter + (uint64_t)i, 200 + i, names[i]);
    assert(write(sockets[1], batch, (size_t)batch_len) == batch_len);
    ap2_mrp_tick(mrp);
    for (int i = 0; i < 6; i++)
        read_response(sockets[1], sender_key, counter + (uint64_t)i, 200 + i);
    assert(commands.count == 5);
    for (int i = 0; i < 5; i++)
        assert(commands.commands[i] == (ap2_remote_command_t)i);
    assert(capture.count == expected_count);
    ap2_mrp_destroy(mrp);
    close(sockets[1]);
}

static void test_modern_transport_events(const uint8_t secret[KEY_SIZE])
{
    static const struct {
        const char *modern;
        const char *legacy;
        int shape; /* 0: root string, 1: integer, 2: boolean, 3: nested, 4: wrong type */
        int expected;
    } cases[] = {
        {"0", NULL, 0, AP2_REMOTE_COMMAND_PLAY},
        {"1", NULL, 0, AP2_REMOTE_COMMAND_PAUSE},
        {"2", NULL, 0, AP2_REMOTE_COMMAND_PLAY_PAUSE},
        {"4", NULL, 0, AP2_REMOTE_COMMAND_NEXT},
        {"5", NULL, 0, AP2_REMOTE_COMMAND_PREVIOUS},
        {"0", "paus", 0, AP2_REMOTE_COMMAND_PAUSE},
        {"0", "unknown", 0, -1},
        {"3", NULL, 0, -1},
        {"6", NULL, 0, -1},
        {"-1", NULL, 0, -1},
        {"00", NULL, 0, -1},
        {"0junk", NULL, 0, -1},
        {"0 ", NULL, 0, -1},
        {"", NULL, 0, -1},
        {"play", NULL, 0, -1},
        {"0", NULL, 1, -1},
        {"0", NULL, 2, -1},
        {"0", NULL, 3, -1},
        {"0", NULL, 4, -1},
        {NULL, NULL, 0, -1},
        {"5", NULL, 0, AP2_REMOTE_COMMAND_PREVIOUS},
    };
    uint8_t receiver_key[KEY_SIZE], sender_key[KEY_SIZE];
    derive_key(secret, "Events-Write-Encryption-Key", receiver_key);
    derive_key(secret, "Events-Read-Encryption-Key", sender_key);
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    struct timeval timeout = {.tv_sec = 2};
    assert(setsockopt(sockets[1], SOL_SOCKET, SO_RCVTIMEO,
                      &timeout, sizeof(timeout)) == 0);
    struct command_capture capture = {0};
    struct ap2_mrp_ctx *mrp = create_mrp_with_callback(
        secret, sockets[0], capture_remote_command, &capture);
    int expected_count = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        ap2_pl_node *root = ap2_pl_dict();
        ap2_pl_dict_set(root, "type", ap2_pl_string(
            cases[i].shape == 4 ? "updateInfo" : "sendMediaRemoteCommand"));
        if (cases[i].legacy)
            ap2_pl_dict_set(root, "value", ap2_pl_string(cases[i].legacy));
        if (cases[i].modern) {
            ap2_pl_node *target = root;
            if (cases[i].shape == 3) {
                target = ap2_pl_dict();
                ap2_pl_dict_set(root, "params", target);
            }
            ap2_pl_node *value = cases[i].shape == 1 ? ap2_pl_int(0) :
                cases[i].shape == 2 ? ap2_pl_bool(false) : ap2_pl_string(cases[i].modern);
            ap2_pl_dict_set(target, "modernMediaRemoteCommand", value);
        }
        uint8_t *body = NULL;
        int body_len = ap2_pl_serialize(root, &body);
        ap2_pl_free(root);
        assert(body_len > 0 && body);
        uint8_t encrypted[1200];
        int len = build_event_request(
            encrypted, sizeof(encrypted), receiver_key, i, 300 + (int)i, body, body_len);
        free(body);
        /* No dispatch before the complete authenticated frame arrives. */
        assert(write(sockets[1], encrypted, 1) == 1);
        ap2_mrp_tick(mrp);
        assert(capture.count == expected_count);
        assert(write(sockets[1], encrypted + 1, (size_t)(len - 1)) == len - 1);
        ap2_mrp_tick(mrp);
        read_response(sockets[1], sender_key, i, 300 + (int)i);
        if (cases[i].expected >= 0) {
            assert(capture.count == expected_count + 1);
            assert(capture.commands[expected_count] == (ap2_remote_command_t)cases[i].expected);
            expected_count++;
        }
        assert(capture.count == expected_count);
        assert(ap2_mrp_event_status(mrp) == 1);
    }
    ap2_mrp_destroy(mrp);
    close(sockets[1]);
}

int main(void)
{
    uint8_t secret[KEY_SIZE];
    for (int i = 0; i < KEY_SIZE; i++) secret[i] = (uint8_t)i;
    uint8_t receiver_key[KEY_SIZE], sender_key[KEY_SIZE];
    derive_key(secret, "Events-Write-Encryption-Key", receiver_key);
    derive_key(secret, "Events-Read-Encryption-Key", sender_key);
    test_artwork_snapshot_generation(secret);
    test_transient_kdf_secret();
    test_volume_events(secret);
    test_modern_transport_events(secret);

    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    struct timeval timeout = {.tv_sec = 2};
    assert(setsockopt(sockets[1], SOL_SOCKET, SO_RCVTIMEO,
                      &timeout, sizeof(timeout)) == 0);
    struct command_capture capture = {0};
    struct ap2_mrp_ctx *mrp = create_mrp_with_callback(
        secret, sockets[0], capture_remote_command, &capture);


    uint8_t encrypted[1200];
    int encrypted_len = build_command_request(
        encrypted, sizeof(encrypted), receiver_key, 0, 42, "play");
    assert(write(sockets[1], encrypted, 1) == 1);
    ap2_mrp_tick(mrp);
    assert(write(sockets[1], encrypted + 1,
                 (size_t)(encrypted_len - 1)) == encrypted_len - 1);
    send_request(sockets[1], receiver_key, 1, 43, "paus");
    ap2_mrp_tick(mrp);
    read_response(sockets[1], sender_key, 0, 42);
    read_response(sockets[1], sender_key, 1, 43);

    static const char *values[] = {"plps", "nitm", "pitm"};
    for (int i = 0; i < 3; i++) {
        send_request(sockets[1], receiver_key, (uint64_t)i + 2,
                     i + 44, values[i]);
        ap2_mrp_tick(mrp);
        read_response(sockets[1], sender_key, (uint64_t)i + 2, i + 44);
    }

    send_request(sockets[1], receiver_key, 5, 47, "unknown");
    ap2_mrp_tick(mrp);
    read_response(sockets[1], sender_key, 5, 47);

    encrypted_len = build_typed_command_request(
        encrypted, sizeof(encrypted), receiver_key, 6, 48,
        "updateInfo", "play");
    assert(write(sockets[1], encrypted, (size_t)encrypted_len) == encrypted_len);
    ap2_mrp_tick(mrp);
    read_response(sockets[1], sender_key, 6, 48);

    encrypted_len = build_embedded_nul_request(
        encrypted, sizeof(encrypted), receiver_key, 7, 49);
    assert(write(sockets[1], encrypted, (size_t)encrypted_len) == encrypted_len);
    ap2_mrp_tick(mrp);
    read_response(sockets[1], sender_key, 7, 49);

    encrypted_len = build_nested_command_request(
        encrypted, sizeof(encrypted), receiver_key, 8, 50);
    assert(write(sockets[1], encrypted, (size_t)encrypted_len) == encrypted_len);
    ap2_mrp_tick(mrp);
    read_response(sockets[1], sender_key, 8, 50);

    uint8_t corrupt_bplist[40] = {0};
    memcpy(corrupt_bplist, "bplist00", 8);
    corrupt_bplist[14] = 1;  /* offset size */
    corrupt_bplist[15] = 1;  /* object-reference size */
    corrupt_bplist[23] = 1;  /* object count */
    corrupt_bplist[39] = 8;  /* invalid offset-table location */
    encrypted_len = build_event_request(
        encrypted, sizeof(encrypted), receiver_key, 9, 51,
        corrupt_bplist, (int)sizeof(corrupt_bplist));
    assert(write(sockets[1], encrypted, (size_t)encrypted_len) == encrypted_len);
    ap2_mrp_tick(mrp);
    read_response(sockets[1], sender_key, 9, 51);

    static const uint8_t invalid_body[] = {'t', 'e', 's', 't'};
    encrypted_len = build_event_request(
        encrypted, sizeof(encrypted), receiver_key, 10, 52,
        invalid_body, (int)sizeof(invalid_body));
    assert(write(sockets[1], encrypted, (size_t)encrypted_len) == encrypted_len);
    ap2_mrp_tick(mrp);
    read_response(sockets[1], sender_key, 10, 52);

    static const ap2_remote_command_t expected_commands[] = {
        AP2_REMOTE_COMMAND_PLAY,
        AP2_REMOTE_COMMAND_PAUSE,
        AP2_REMOTE_COMMAND_PLAY_PAUSE,
        AP2_REMOTE_COMMAND_NEXT,
        AP2_REMOTE_COMMAND_PREVIOUS,
    };
    static const char *expected_names[] = {
        "play", "pause", "play_pause", "next", "previous",
    };
    assert(capture.count == 5);
    for (int i = 0; i < capture.count; i++) {
        assert(capture.commands[i] == expected_commands[i]);
        assert(strcmp(
                   ap2_remote_command_name(capture.commands[i]),
                   expected_names[i]) == 0);
    }


    ap2_mrp_destroy(mrp);
    close(sockets[1]);

    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    mrp = create_mrp(secret, sockets[0]);
    close(sockets[1]);
    ap2_mrp_tick(mrp);
    assert(ap2_mrp_event_status(mrp) == 0);
    ap2_mrp_destroy(mrp);

    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    int small_buffer = 1024;
    assert(setsockopt(sockets[0], SOL_SOCKET, SO_SNDBUF,
                     &small_buffer, sizeof(small_buffer)) == 0);
    assert(setsockopt(sockets[1], SOL_SOCKET, SO_RCVBUF,
                     &small_buffer, sizeof(small_buffer)) == 0);
    mrp = create_mrp(secret, sockets[0]);
    uint64_t counter = 0;
    for (int batch = 0;
         batch < 20 && ap2_mrp_event_status(mrp) == 1;
         batch++) {
        for (int i = 0; i < 10; i++, counter++)
            send_request(sockets[1], receiver_key, counter,
                         100 + (int)counter, "play");
        ap2_mrp_tick(mrp);
    }
    assert(ap2_mrp_event_status(mrp) == 0);
    ap2_mrp_destroy(mrp);
    close(sockets[1]);
    return 0;
}
