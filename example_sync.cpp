////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#include <string>

typedef void* srs_error_t;
#define srs_assert (void)
#define srs_success 0 // SrsCplxError::success()
#define srs_error_new(ret, fmt, ...) (void*)(int64_t)ret
#define srs_error_wrap(err, fmt, ...) (void*)(int64_t)1
#define ERROR_PB_NO_SPACE               1084
#define srs_freep(p) if (p) { delete p; p = NULL; } (void)0

/**
 * bytes utility, used to:
 * convert basic types to bytes,
 * build basic types from bytes.
 * @remark the buffer never mange the bytes, user must manage it.
 */
class SrsBuffer
{
private:
    // current position at bytes.
    char* p;
    // the bytes data for buffer to read or write.
    char* bytes;
    // the total number of bytes.
    int nb_bytes;
public:
    // Create buffer with data b and size nn.
    // @remark User must free the data b.
    SrsBuffer(char* b, int nn);
    ~SrsBuffer();
public:
    // Copy the object, keep position of buffer.
    SrsBuffer* copy();
    // Get the data and head of buffer.
    //      current-bytes = head() = data() + pos()
    char* data();
    char* head();
    // Get the total size of buffer.
    //      left-bytes = size() - pos()
    int size();
    void set_size(int v);
    // Get the current buffer position.
    int pos();
    // Left bytes in buffer, total size() minus the current pos().
    int left();
    // Whether buffer is empty.
    bool empty();
    // Whether buffer is able to supply required size of bytes.
    // @remark User should check buffer by require then do read/write.
    // @remark Assert the required_size is not negative.
    bool require(int required_size);
public:
    // Skip some size.
    // @param size can be any value. positive to forward; negative to backward.
    // @remark to skip(pos()) to reset buffer.
    // @remark assert initialized, the data() not NULL.
    void skip(int size);
public:
    // Read 1bytes char from buffer.
    int8_t read_1bytes();
    // Read 2bytes int from buffer.
    int16_t read_2bytes();
    int16_t read_le2bytes();
    // Read 3bytes int from buffer.
    int32_t read_3bytes();
    int32_t read_le3bytes();
    // Read 4bytes int from buffer.
    int32_t read_4bytes();
    int32_t read_le4bytes();
    // Read 8bytes int from buffer.
    int64_t read_8bytes();
    int64_t read_le8bytes();
    // Read string from buffer, length specifies by param len.
    std::string read_string(int len);
    // Read bytes from buffer, length specifies by param len.
    void read_bytes(char* data, int size);
public:
    // Write 1bytes char to buffer.
    void write_1bytes(int8_t value);
    // Write 2bytes int to buffer.
    void write_2bytes(int16_t value);
    void write_le2bytes(int16_t value);
    // Write 4bytes int to buffer.
    void write_4bytes(int32_t value);
    void write_le4bytes(int32_t value);
    // Write 3bytes int to buffer.
    void write_3bytes(int32_t value);
    void write_le3bytes(int32_t value);
    // Write 8bytes int to buffer.
    void write_8bytes(int64_t value);
    void write_le8bytes(int64_t value);
    // Write string to buffer
    void write_string(std::string value);
    // Write bytes to buffer
    void write_bytes(char* data, int size);
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////#include <string>
#include <string>
#include <map>
#include <algorithm>
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

// See https://cloud.tencent.com/document/product/614/12445
namespace tencentcloud_api_sign {
    std::string sha1(const void *data, size_t len) {
        unsigned char digest[SHA_DIGEST_LENGTH];
        SHA_CTX ctx;
        SHA1_Init(&ctx);
        SHA1_Update(&ctx, data, len);
        SHA1_Final(digest, &ctx);
        char c_sha1[SHA_DIGEST_LENGTH*2+1];
        for (unsigned i = 0; i < SHA_DIGEST_LENGTH; ++i) {
            sprintf(&c_sha1[i*2], "%02x", (unsigned int)digest[i]);
        }
        return c_sha1;
    }

    std::string hmac_sha1(const char *key, const void *data, size_t len) {
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned digest_len;
        char c_hmacsha1[EVP_MAX_MD_SIZE*2+1];
#if !defined(OPENSSL_VERSION_NUMBER) || OPENSSL_VERSION_NUMBER < 0x10100000L
        HMAC_CTX ctx;
        HMAC_CTX_init(&ctx);
        HMAC_Init_ex(&ctx, key, strlen(key), EVP_sha1(), NULL);
        HMAC_Update(&ctx, (unsigned char*)data, len);
        HMAC_Final(&ctx, digest, &digest_len);
        HMAC_CTX_cleanup(&ctx);
#else
        HMAC_CTX *ctx = HMAC_CTX_new();
        HMAC_CTX_reset(ctx);
        HMAC_Init_ex(ctx, key, strlen(key), EVP_sha1(), NULL);
        HMAC_Update(ctx, (unsigned char *)data, len);
        HMAC_Final(ctx, digest, &digest_len);
        HMAC_CTX_free(ctx);
#endif
        for (unsigned i = 0; i != digest_len; ++i) {
            sprintf(&c_hmacsha1[i*2], "%02x", (unsigned int)digest[i]);
        }
        return c_hmacsha1;
    }

    std::string urlencode(const char *s) {
        static unsigned char hexchars[] = "0123456789ABCDEF";
        size_t length = strlen(s), pos = 0;
        unsigned char c_url[length*3+1];
        const unsigned char *p = (const unsigned char *)s;
        for (; *p; ++p) {
            if (isalnum((unsigned char)*p) || (*p == '-') ||
                (*p == '_') || (*p == '.') || (*p == '~')) {
                c_url[pos++] = *p;
            } else {
                c_url[pos++] = '%';
                c_url[pos++] = hexchars[(*p)>>4];
                c_url[pos++] = hexchars[(*p)&15U];
            }
        }
        c_url[pos] = 0;
        return (char*)c_url;
    }

    std::string signature(const std::string &secret_id,
                          const std::string &secret_key,
                          std::string method,
                          const std::string &path,
                          const std::map<std::string, std::string> &params,
                          const std::map<std::string, std::string> &headers,
                          long expire) {

        const size_t SIGNLEN = 1024;
        std::string http_request_info, uri_parm_list,
                header_list, str_to_sign, sign_key;
        transform(method.begin(), method.end(), method.begin(), ::tolower);
        http_request_info.reserve(SIGNLEN);
        http_request_info.append(method).append("\n").append(path).append("\n");
        uri_parm_list.reserve(SIGNLEN);
        std::map<std::string, std::string>::const_iterator iter;
        for (iter = params.begin();
             iter != params.end(); ) {
            uri_parm_list.append(iter->first);
            http_request_info.append(iter->first).append("=")
                    .append(urlencode(iter->second.c_str()));
            if (++iter != params.end()) {
                uri_parm_list.append(";");
                http_request_info.append("&");
            }
        }
        http_request_info.append("\n");
        header_list.reserve(SIGNLEN);
        for (iter = headers.begin();
             iter != headers.end(); ++iter) {
            sign_key = iter->first;
            transform(sign_key.begin(), sign_key.end(), sign_key.begin(), ::tolower);
            if (sign_key == "content-type" || sign_key == "content-md5"
                || sign_key == "host" || sign_key[0] == 'x') {
                header_list.append(sign_key);
                http_request_info.append(sign_key).append("=")
                        .append(urlencode(iter->second.c_str()));
                header_list.append(";");
                http_request_info.append("&");
            }
        }
        if (!header_list.empty()) {
            header_list[header_list.size() - 1] = 0;
            http_request_info[http_request_info.size() - 1] = '\n';
        }
        //printf("%s\nEOF\n", http_request_info.c_str());
        char signed_time[SIGNLEN];
        int signed_time_len = snprintf(signed_time, SIGNLEN,
                                       "%lu;%lu", time(0) - 60, time(0) + expire);
        //snprintf(signed_time, SIGNLEN, "1510109254;1510109314");
        std::string signkey = hmac_sha1(secret_key.c_str(),
                                        signed_time, signed_time_len);
        str_to_sign.reserve(SIGNLEN);
        str_to_sign.append("sha1").append("\n")
                .append(signed_time).append("\n")
                .append(sha1(http_request_info.c_str(), http_request_info.size()))
                .append("\n");
        //printf("%s\nEOF\n", str_to_sign.c_str());
        char c_signature[SIGNLEN];
        snprintf(c_signature, SIGNLEN,
                 "q-sign-algorithm=sha1&q-ak=%s"
                 "&q-sign-time=%s&q-key-time=%s"
                 "&q-header-list=%s&q-url-param-list=%s&q-signature=%s",
                 secret_id.c_str(), signed_time, signed_time,
                 header_list.c_str(), uri_parm_list.c_str(),
                 hmac_sha1(signkey.c_str(), str_to_sign.c_str(),
                           str_to_sign.size()).c_str());
        return c_signature;
    }
}

std::string srs_cloud_to_querystring(std::map<std::string, std::string>& params) {
    std::string v;
    for (std::map<std::string, std::string>::iterator it = params.begin(); it != params.end(); ++it) {
        if (it != params.begin()) {
            v.append("&");
        }
        v.append(it->first);
        v.append("=");
        v.append(tencentcloud_api_sign::urlencode(it->second.c_str()));
    }
    return v;
}

void srs_cloud_sign_request(
        const std::string& host, const std::string& ak_id, const std::string& ak_secret,
        const std::string& path, const std::string& method, const std::string& topic,
        std::map<std::string, std::string>& params, std::map<std::string, std::string>& headers
) {
    params["topic_id"] = topic;

    headers["Host"] = host;
    headers["UserAgent"] = "tencent-log-sdk-cpp v1.0.1";
    headers["Content-Type"] = "application/x-protobuf";

    std::string signature = tencentcloud_api_sign::signature(
            ak_id, ak_secret, method, path, params, headers,
            300 // Expire in seconds
    );
    headers["Authorization"] = signature;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#include <string>
#include <vector>
#include <sstream>

// See https://developers.google.com/protocol-buffers/docs/encoding#varints
class SrsProtobufVarints
{
private:
    // See Go bits.Len64 of package math/bits.
    static int bits_len64(uint64_t x) {
        // See Go bits.len8tab of package math/bits.
        static uint8_t bits_len8tab[256] = {
            0x00, 0x01, 0x02, 0x02, 0x03, 0x03, 0x03, 0x03, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
            0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
            0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
            0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
            0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
            0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
            0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
            0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
            0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
            0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
            0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
            0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
            0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
            0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
            0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
            0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
        };

        int n = 0;
        if (x >= (uint64_t)1<<32) {
            x >>= 32;
            n = 32;
        }
        if (x >= (uint64_t)1<<16) {
            x >>= 16;
            n += 16;
        }
        if (x >= (uint64_t)1<<8) {
            x >>= 8;
            n += 8;
        }
        return n + int(bits_len8tab[x]);
    }
public:
    // See Go protowire.SizeVarint of package google.golang.org/protobuf/encoding/protowire
    static int sizeof_varint(uint64_t v) {
        int n = bits_len64(v);
        return int(9 * uint32_t(n) + 64) / 64;
    }
    // See Go protowire.AppendVarint of package google.golang.org/protobuf/encoding/protowire
    static srs_error_t encode(SrsBuffer* b, uint64_t v) {
        srs_error_t err = srs_success;

        if (!b->require(SrsProtobufVarints::sizeof_varint(v))) {
            return srs_error_new(ERROR_PB_NO_SPACE, "require %d only %d bytes", v, b->left());
        }

        if (v < (uint64_t)1<<7) {
            b->write_1bytes((uint8_t)v);
        } else if (v < (uint64_t)1<<14) {
            b->write_1bytes((uint8_t)((v>>0)&0x7f|0x80));
            b->write_1bytes((uint8_t)(v>>7));
        } else if (v < (uint64_t)1<<21) {
            b->write_1bytes((uint8_t)((v>>0)&0x7f|0x80));
            b->write_1bytes((uint8_t)((v>>7)&0x7f|0x80));
            b->write_1bytes((uint8_t)((v>>14)&0x7f|0x80));
            b->write_1bytes((uint8_t)(v>>21));
        } else if (v < (uint64_t)1<<35) {
            b->write_1bytes((uint8_t)((v>>0)&0x7f|0x80));
            b->write_1bytes((uint8_t)((v>>7)&0x7f|0x80));
            b->write_1bytes((uint8_t)((v>>14)&0x7f|0x80));
            b->write_1bytes((uint8_t)((v>>21)&0x7f|0x80));
            b->write_1bytes((uint8_t)(v>>28));
        } else if (v < (uint64_t)1<<42) {
			b->write_1bytes((uint8_t)((v>>0)&0x7f|0x80));
			b->write_1bytes((uint8_t)((v>>7)&0x7f|0x80));
			b->write_1bytes((uint8_t)((v>>14)&0x7f|0x80));
			b->write_1bytes((uint8_t)((v>>21)&0x7f|0x80));
			b->write_1bytes((uint8_t)((v>>28)&0x7f|0x80));
			b->write_1bytes((uint8_t)(v>>35));
        } else if (v < (uint64_t)1<<49) {
			b->write_1bytes((uint8_t)((v>>0)&0x7f|0x80));
			b->write_1bytes((uint8_t)((v>>7)&0x7f|0x80));
			b->write_1bytes((uint8_t)((v>>14)&0x7f|0x80));
			b->write_1bytes((uint8_t)((v>>21)&0x7f|0x80));
			b->write_1bytes((uint8_t)((v>>28)&0x7f|0x80));
			b->write_1bytes((uint8_t)((v>>35)&0x7f|0x80));
			b->write_1bytes((uint8_t)(v>>42));
        } else if(v < (uint64_t)1<<56) {
			b->write_1bytes((uint8_t)((v>>0)&0x7f|0x80));
			b->write_1bytes((uint8_t)((v>>7)&0x7f|0x80));
			b->write_1bytes((uint8_t)((v>>14)&0x7f|0x80));
			b->write_1bytes((uint8_t)((v>>21)&0x7f|0x80));
			b->write_1bytes((uint8_t)((v>>28)&0x7f|0x80));
			b->write_1bytes((uint8_t)((v>>35)&0x7f|0x80));
			b->write_1bytes((uint8_t)((v>>42)&0x7f|0x80));
			b->write_1bytes((uint8_t)(v>>49));
        } else if (v < (uint64_t)1<<63) {
			b->write_1bytes((uint8_t)((v>>0)&0x7f|0x80));
			b->write_1bytes((uint8_t)((v>>7)&0x7f|0x80));
			b->write_1bytes((uint8_t)((v>>14)&0x7f|0x80));
			b->write_1bytes((uint8_t)((v>>21)&0x7f|0x80));
			b->write_1bytes((uint8_t)((v>>28)&0x7f|0x80));
			b->write_1bytes((uint8_t)((v>>35)&0x7f|0x80));
			b->write_1bytes((uint8_t)((v>>42)&0x7f|0x80));
			b->write_1bytes((uint8_t)((v>>49)&0x7f|0x80));
			b->write_1bytes((uint8_t)(v>>56));
        } else {
			b->write_1bytes((uint8_t)((v>>0)&0x7f|0x80));
			b->write_1bytes((uint8_t)((v>>7)&0x7f|0x80));
			b->write_1bytes((uint8_t)((v>>14)&0x7f|0x80));
			b->write_1bytes((uint8_t)((v>>21)&0x7f|0x80));
			b->write_1bytes((uint8_t)((v>>28)&0x7f|0x80));
			b->write_1bytes((uint8_t)((v>>35)&0x7f|0x80));
			b->write_1bytes((uint8_t)((v>>42)&0x7f|0x80));
			b->write_1bytes((uint8_t)((v>>49)&0x7f|0x80));
			b->write_1bytes((uint8_t)((v>>56)&0x7f|0x80));
			b->write_1bytes((uint8_t)1);
        }

        return err;
    }
};

class SrsProtobufString
{
public:
    // See Go protowire.SizeBytes of package google.golang.org/protobuf/encoding/protowire
    static int sizeof_string(const std::string& v) {
        uint64_t n = v.length();
        return SrsProtobufVarints::sizeof_varint(uint64_t(n)) + n;
    }
    // See Go protowire.AppendString of package google.golang.org/protobuf/encoding/protowire
    static srs_error_t encode(SrsBuffer* b, const std::string& v) {
        srs_error_t  err = srs_success;

        uint64_t n = v.length();
        if ((err = SrsProtobufVarints::encode(b, n)) != srs_success) {
            return srs_error_wrap(err, "string size %d", n);
        }

        if (!b->require(n)) {
            return srs_error_new(ERROR_PB_NO_SPACE, "require %d only %d byte", n, b->left());
        }
        b->write_string(v);

        return err;
    }
};

// See https://cloud.tencent.com/document/product/614/59470
class SrsClsLogContent
{
private:
    // required string key = 1;
    std::string key_;
    // required string value = 2;
    std::string value_;
public:
    SrsClsLogContent() {
    }
    ~SrsClsLogContent() {
    }
public:
    SrsClsLogContent* set_key(std::string v) {
        key_ = v;
        return this;
    }
    SrsClsLogContent* set_value(std::string v) {
        value_ = v;
        return this;
    }
public:
    virtual uint64_t nb_bytes() {
        uint64_t  nn = 1 + SrsProtobufString::sizeof_string(key_);
        nn += 1 + SrsProtobufString::sizeof_string(value_);
        return nn;
    }
    srs_error_t encode(SrsBuffer* b) {
        srs_error_t err = srs_success;

        // Encode the field key as [ID=1, TYPE=2(Length delimited)]
        if (!b->require(1)) {
            return srs_error_new(ERROR_PB_NO_SPACE, "require 1 byte");
        }
        b->write_1bytes(0x0a);

        if ((err = SrsProtobufString::encode(b, key_)) != srs_success) {
            return srs_error_wrap(err, "encode key=%s", source_.c_str());
        }

        // Encode the field value as [ID=2, TYPE=2(Length delimited)]
        if (!b->require(1)) {
            return srs_error_new(ERROR_PB_NO_SPACE, "require 1 byte");
        }
        b->write_1bytes(0x12);

        if ((err = SrsProtobufString::encode(b, value_)) != srs_success) {
            return srs_error_wrap(err, "encode value=%s", source_.c_str());
        }

        return err;
    }
};

// See https://cloud.tencent.com/document/product/614/59470
class SrsClsLog
{
private:
    // required int64 time = 1;
    int64_t time_;
    // repeated Content contents= 2;
    std::vector<SrsClsLogContent*> contents_;
public:
    SrsClsLog() {
    }
    ~SrsClsLog() {
        for (std::vector<SrsClsLogContent*>::iterator it = contents_.begin(); it != contents_.end(); ++it) {
            SrsClsLogContent* content = *it;
            srs_freep(content);
        }
    }
public:
    SrsClsLogContent* add_content() {
        SrsClsLogContent* content = new SrsClsLogContent();
        contents_.push_back(content);
        return content;
    }
    SrsClsLog* set_time(int64_t v) {
        time_ = v;
        return this;
    }
public:
    virtual uint64_t nb_bytes() {
        uint64_t nn = 1 + SrsProtobufVarints::sizeof_varint(time_);

        for (std::vector<SrsClsLogContent*>::iterator it = contents_.begin(); it != contents_.end(); ++it) {
            SrsClsLogContent* content = *it;
            uint64_t size = content->nb_bytes();
            nn += 1 + SrsProtobufVarints::sizeof_varint(size) + size;
        }

        return nn;
    }
    srs_error_t encode(SrsBuffer* b) {
        srs_error_t  err = srs_success;

        // Encode the field time as [ID=1, TYPE=0(Varint)]
        if (!b->require(1)) {
            return srs_error_new(ERROR_PB_NO_SPACE, "require 1 byte");
        }
        b->write_1bytes(0x08);

        if ((err = SrsProtobufVarints::encode(b, time_)) != srs_success) {
            return srs_error_wrap(err, "encode time");
        }

        // Encode each content.
        for (std::vector<SrsClsLogContent*>::iterator it = contents_.begin(); it != contents_.end(); ++it) {
            SrsClsLogContent* content = *it;

            // Encode the field contents as [ID=2, TYPE=2(Length delimited)]
            if (!b->require(1)) {
                return srs_error_new(ERROR_PB_NO_SPACE, "require 1 byte");
            }
            b->write_1bytes(0x12);

            // Encode the varint size of children.
            uint64_t size = content->nb_bytes();
            if ((err = SrsProtobufVarints::encode(b, size)) != srs_success) {
                return srs_error_wrap(err, "encode size=%d", (int)size);
            }

            // Encode the content itself.
            if ((err = content->encode(b)) != srs_success) {
                return srs_error_wrap(err, "encode content");
            }
        }

        return err;
    }
};

// See https://cloud.tencent.com/document/product/614/59470
class SrsClsLogGroup
{
private:
    // repeated Log logs= 1;
    std::vector<SrsClsLog*> logs_;
    // optional string source = 4;
    std::string source_;
public:
    SrsClsLogGroup() {
    }
    ~SrsClsLogGroup() {
        for (std::vector<SrsClsLog*>::iterator it = logs_.begin(); it != logs_.end(); ++it) {
            SrsClsLog* log = *it;
            srs_freep(log);
        }
    }
public:
    SrsClsLogGroup* set_source(std::string v) {
        source_ = v;
        return this;
    }
    SrsClsLog* add_log() {
        SrsClsLog* log = new SrsClsLog();
        logs_.push_back(log);
        return log;
    }
public:
    virtual uint64_t nb_bytes() {
        uint64_t nn = 0;
        for (std::vector<SrsClsLog*>::iterator it = logs_.begin(); it != logs_.end(); ++it) {
            SrsClsLog* log = *it;
            uint64_t size = log->nb_bytes();
            nn += 1 + SrsProtobufVarints::sizeof_varint(size) + size;
        }

        nn += 1 + SrsProtobufString::sizeof_string(source_);
        return nn;
    }
    srs_error_t encode(SrsBuffer* b) {
        srs_error_t err = srs_success;

        // Encode each log.
        for (std::vector<SrsClsLog*>::iterator it = logs_.begin(); it != logs_.end(); ++it) {
            SrsClsLog* log = *it;

            // Encode the field logs as [ID=1, TYPE=2(Length delimited)]
            if (!b->require(1)) {
                return srs_error_new(ERROR_PB_NO_SPACE, "require 1 byte");
            }
            b->write_1bytes(0x0a);

            // Encode the varint size of children.
            uint64_t size = log->nb_bytes();
            if ((err = SrsProtobufVarints::encode(b, size)) != srs_success) {
                return srs_error_wrap(err, "encode size=%d", (int)size);
            }

            // Encode the log itself.
            if ((err = log->encode(b)) != srs_success) {
                return srs_error_wrap(err, "encode log");
            }
        }

        // Encode the field source as [ID=4, TYPE=2(Length delimited)]
        if (!b->require(1)) {
            return srs_error_new(ERROR_PB_NO_SPACE, "require 1 byte");
        }
        b->write_1bytes(0x22);

        if ((err = SrsProtobufString::encode(b, source_)) != srs_success) {
            return srs_error_wrap(err, "encode source=%s", source_.c_str());
        }

        return err;
    }
};

// See https://cloud.tencent.com/document/product/614/59470
class SrsClsLogGroupList
{
private:
    // repeated LogGroup logGroupList = 1;
    std::vector<SrsClsLogGroup*> groups_;
public:
    SrsClsLogGroupList() {
    }
    ~SrsClsLogGroupList() {
        for (std::vector<SrsClsLogGroup*>::iterator it = groups_.begin(); it != groups_.end(); ++it) {
            SrsClsLogGroup* group = *it;
            srs_freep(group);
        }
    }
public:
    SrsClsLogGroup* add_log_group() {
        SrsClsLogGroup* group = new SrsClsLogGroup();
        groups_.push_back(group);
        return group;
    }
public:
    virtual uint64_t nb_bytes() {
        uint64_t nn = 0;
        for (std::vector<SrsClsLogGroup*>::iterator it = groups_.begin(); it != groups_.end(); ++it) {
            SrsClsLogGroup* group = *it;
            uint64_t size = group->nb_bytes();
            nn += 1 + SrsProtobufVarints::sizeof_varint(size) + size;
        }
        return nn;
    }
    srs_error_t encode(SrsBuffer* b) {
        srs_error_t err = srs_success;

        // Encode each group.
        for (std::vector<SrsClsLogGroup*>::iterator it = groups_.begin(); it != groups_.end(); ++it) {
            SrsClsLogGroup* group = *it;

            // Encode the field groups as [ID=1, TYPE=2(Length delimited)]
            if (!b->require(1)) {
                return srs_error_new(ERROR_PB_NO_SPACE, "require 1 byte");
            }
            b->write_1bytes(0x0a);

            // Encode the varint size of children.
            uint64_t size = group->nb_bytes();
            if ((err = SrsProtobufVarints::encode(b, size)) != srs_success) {
                return srs_error_wrap(err, "encode size=%d", (int)size);
            }

            // Encode the log group itself.
            if ((err = group->encode(b)) != srs_success) {
                return srs_error_wrap(err, "encode group");
            }
        }

        return err;
    }
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
using namespace std;

SrsBuffer::SrsBuffer(char* b, int nn)
{
    p = bytes = b;
    nb_bytes = nn;
}

SrsBuffer::~SrsBuffer()
{
}

SrsBuffer* SrsBuffer::copy()
{
    SrsBuffer* cp = new SrsBuffer(bytes, nb_bytes);
    cp->p = p;
    return cp;
}

char* SrsBuffer::data()
{
    return bytes;
}

char* SrsBuffer::head()
{
    return p;
}

int SrsBuffer::size()
{
    return nb_bytes;
}

void SrsBuffer::set_size(int v)
{
    nb_bytes = v;
}

int SrsBuffer::pos()
{
    return (int)(p - bytes);
}

int SrsBuffer::left()
{
    return nb_bytes - (int)(p - bytes);
}

bool SrsBuffer::empty()
{
    return !bytes || (p >= bytes + nb_bytes);
}

bool SrsBuffer::require(int required_size)
{
    if (required_size < 0) {
        return false;
    }

    return required_size <= nb_bytes - (p - bytes);
}

void SrsBuffer::skip(int size)
{
    srs_assert(p);
    srs_assert(p + size >= bytes);
    srs_assert(p + size <= bytes + nb_bytes);

    p += size;
}

int8_t SrsBuffer::read_1bytes()
{
    srs_assert(require(1));

    return (int8_t)*p++;
}

int16_t SrsBuffer::read_2bytes()
{
    srs_assert(require(2));

    int16_t value;
    char* pp = (char*)&value;
    pp[1] = *p++;
    pp[0] = *p++;

    return value;
}

int16_t SrsBuffer::read_le2bytes()
{
    srs_assert(require(2));

    int16_t value;
    char* pp = (char*)&value;
    pp[0] = *p++;
    pp[1] = *p++;

    return value;
}

int32_t SrsBuffer::read_3bytes()
{
    srs_assert(require(3));

    int32_t value = 0x00;
    char* pp = (char*)&value;
    pp[2] = *p++;
    pp[1] = *p++;
    pp[0] = *p++;

    return value;
}

int32_t SrsBuffer::read_le3bytes()
{
    srs_assert(require(3));

    int32_t value = 0x00;
    char* pp = (char*)&value;
    pp[0] = *p++;
    pp[1] = *p++;
    pp[2] = *p++;

    return value;
}

int32_t SrsBuffer::read_4bytes()
{
    srs_assert(require(4));

    int32_t value;
    char* pp = (char*)&value;
    pp[3] = *p++;
    pp[2] = *p++;
    pp[1] = *p++;
    pp[0] = *p++;

    return value;
}

int32_t SrsBuffer::read_le4bytes()
{
    srs_assert(require(4));

    int32_t value;
    char* pp = (char*)&value;
    pp[0] = *p++;
    pp[1] = *p++;
    pp[2] = *p++;
    pp[3] = *p++;

    return value;
}

int64_t SrsBuffer::read_8bytes()
{
    srs_assert(require(8));

    int64_t value;
    char* pp = (char*)&value;
    pp[7] = *p++;
    pp[6] = *p++;
    pp[5] = *p++;
    pp[4] = *p++;
    pp[3] = *p++;
    pp[2] = *p++;
    pp[1] = *p++;
    pp[0] = *p++;

    return value;
}

int64_t SrsBuffer::read_le8bytes()
{
    srs_assert(require(8));

    int64_t value;
    char* pp = (char*)&value;
    pp[0] = *p++;
    pp[1] = *p++;
    pp[2] = *p++;
    pp[3] = *p++;
    pp[4] = *p++;
    pp[5] = *p++;
    pp[6] = *p++;
    pp[7] = *p++;

    return value;
}

string SrsBuffer::read_string(int len)
{
    srs_assert(require(len));

    std::string value;
    value.append(p, len);

    p += len;

    return value;
}

void SrsBuffer::read_bytes(char* data, int size)
{
    srs_assert(require(size));

    memcpy(data, p, size);

    p += size;
}

void SrsBuffer::write_1bytes(int8_t value)
{
    srs_assert(require(1));

    *p++ = value;
}

void SrsBuffer::write_2bytes(int16_t value)
{
    srs_assert(require(2));

    char* pp = (char*)&value;
    *p++ = pp[1];
    *p++ = pp[0];
}

void SrsBuffer::write_le2bytes(int16_t value)
{
    srs_assert(require(2));

    char* pp = (char*)&value;
    *p++ = pp[0];
    *p++ = pp[1];
}

void SrsBuffer::write_4bytes(int32_t value)
{
    srs_assert(require(4));

    char* pp = (char*)&value;
    *p++ = pp[3];
    *p++ = pp[2];
    *p++ = pp[1];
    *p++ = pp[0];
}

void SrsBuffer::write_le4bytes(int32_t value)
{
    srs_assert(require(4));

    char* pp = (char*)&value;
    *p++ = pp[0];
    *p++ = pp[1];
    *p++ = pp[2];
    *p++ = pp[3];
}

void SrsBuffer::write_3bytes(int32_t value)
{
    srs_assert(require(3));

    char* pp = (char*)&value;
    *p++ = pp[2];
    *p++ = pp[1];
    *p++ = pp[0];
}

void SrsBuffer::write_le3bytes(int32_t value)
{
    srs_assert(require(3));

    char* pp = (char*)&value;
    *p++ = pp[0];
    *p++ = pp[1];
    *p++ = pp[2];
}

void SrsBuffer::write_8bytes(int64_t value)
{
    srs_assert(require(8));

    char* pp = (char*)&value;
    *p++ = pp[7];
    *p++ = pp[6];
    *p++ = pp[5];
    *p++ = pp[4];
    *p++ = pp[3];
    *p++ = pp[2];
    *p++ = pp[1];
    *p++ = pp[0];
}

void SrsBuffer::write_le8bytes(int64_t value)
{
    srs_assert(require(8));

    char* pp = (char*)&value;
    *p++ = pp[0];
    *p++ = pp[1];
    *p++ = pp[2];
    *p++ = pp[3];
    *p++ = pp[4];
    *p++ = pp[5];
    *p++ = pp[6];
    *p++ = pp[7];
}

void SrsBuffer::write_string(string value)
{
    srs_assert(require((int)value.length()));

    memcpy(p, value.data(), value.length());
    p += value.length();
}

void SrsBuffer::write_bytes(char* data, int size)
{
    srs_assert(require(size));

    memcpy(p, data, size);
    p += size;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#include <stdlib.h>
#include "client.h"
#include "common.h"
#include "cls_logs.pb.h"
#include <string>
#include <iostream>
#include <unistd.h>
#include <memory>

using namespace tencent_log_sdk_cpp_v2;
using namespace std;

class UserResult : public CallBack {
public:
    UserResult() = default;

    ~UserResult() = default;

    void Success(PostLogStoreLogsResponse result) override { std::cout << result.Printf() << std::endl; }

    void Fail(PostLogStoreLogsResponse result) override {
        std::cout << result.Printf() << std::endl;
        std::cout << result.loggroup_.ShortDebugString().c_str() << std::endl;
    }
};

#include "adapter.h"
PostLogStoreLogsResponse send_logs(string topic, string data, string endpoint, string ak_id, string ak_secret) {
    string path = "/structuredlog";
    string method = "POST";

    std::map<string, string> params;
    std::map<string, string> headers;
    srs_cloud_sign_request(endpoint, ak_id, ak_secret, path, method, topic, params, headers);

    string queryString = srs_cloud_to_querystring(params);

    HttpMessage httpResponse;
    curl_off_t mMaxSendSpeedInBytePerSec = 1024 * 1024 * 1024;
    LOGAdapter::Send(method, endpoint, 80, path, queryString, headers, data,
        LOG_REQUEST_TIMEOUT, LOG_CONNECT_TIMEOUT, httpResponse,
             mMaxSendSpeedInBytePerSec);

    PostLogStoreLogsResponse ret;
    ret.bodyBytes = data.size();
    ret.statusCode = httpResponse.statusCode;
    ret.requestId = httpResponse.header["X-Cls-Requestid"];
    ret.content = httpResponse.content;
    ret.header = httpResponse.header;
    return ret;
}

int main(int argc, char **argv) {
    std::string region = getenv("REGION") ? getenv("REGION") : "ap-guangzhou";
    std::string ak_id = getenv("AKID") ? getenv("AKID") : "";
    std::string ak_secret = getenv("AKSECRET") ? getenv("AKSECRET") : "";
    std::string topic = getenv("TOPIC") ? getenv("TOPIC") : "";

    string endpoint = region + ".cls.tencentcs.com";
    cout << "region:" << region << ", endpoint:" << endpoint << ", ak:" << ak_id << ", secret:" << ak_secret.length()
         << "B" << ", topic:" << topic << endl;
    if (ak_id.empty() || ak_secret.empty() || topic.empty()) {
        cout << "No config" << endl;
        exit(-1);
    }

    std::shared_ptr<LOGClient> ptr = std::make_shared<LOGClient>(
            endpoint, ak_id, ak_secret,
            LOG_REQUEST_TIMEOUT, LOG_CONNECT_TIMEOUT,
            "127.0.0.1", false
    );

    auto now = time(NULL);
    printf("now=%lx\n", now);

    // Log in PB, see https://developers.google.com/protocol-buffers/docs/encoding
    //
    // For only one log content:
    //      0a 30 (LogGroupList.logGroupList, ID=1, LD=0x30=48B)
    //          0a 23 (LogGroup.logs, ID=1, LD=0x23=35B)
    //              08 (Log.time, ID=1, VAR = 0x62ece79d = 1659692957 Friday, August 5, 2022 9:49:17 AM)
    //                  9d cf b3 97 06
    //              12 1b (Log.contents, ID=2, LD=0x1b=27B)
    //                  0a 07 (Content.key, ID=1, LD=0x07=7B)
    //                      63 6f 6e 74 65 6e 74 (string="content")
    //                  12 10 (Content.value, ID=2, LD=0x10=16B)
    //                      74 68 69 73 20 6d 79 20 74 65 73 74 20 6c 6f 67 (string="this my test log")
    //          22 09 (LogGroup.source, ID=4, LD=0x09=9B)
    //              31 32 37 2e 30 2e 30 2e 31 (string="127.0.0.1")
    //
    // For three log contents:
    //      0a 52 (LogGroupList.logGroupList, ID=1, LD=0x52=82B)
    //          0a 45 (LogGroup.logs, ID=1, LD=0x45=69B)
    //              08 (Log.time, ID=1, VAR)
    //                  f1 c9 b9 97 06
    //              12 1b (Log.contents, ID=2, LD=0x1b=27B)
    //                  0a 07 (Content.key, ID=1, LD=0x07=7B)
    //                      63 6f 6e 74 65 6e 74 (string="content")
    //                  12 10 (Content.value, ID=2, LD=0x10=16B)
    //                      74 68 69 73 20 6d 79 20 74 65 73 74 20 6c 6f 67 (string="this my test log")
    //              12 12 (Log.contents, ID=2, LD=0x12=18B)
    //                  0a 07 (Content.key, ID=1, LD=0x07=7B)
    //                      76 65 72 73 69 6f 6e (string="version")
    //                  12 07 (Content.value, ID=2, LD=0x07=7B)
    //                      76 35 2e 30 2e 33 35 (string="v5.0.35")
    //              12 0c (Log.contents, ID=2, LD=0x0c=12B)
    //                  0a 06 (Content.key, ID=1, LD=0x06=6B)
    //                      72 65 67 69 6f 6e (string="region")
    //                  12 02 (Content.value, ID=2, LD=0x02=2B)
    //                      63 6e (string="cn")
    //          22 09 (LogGroup.source, ID=4, LD=0x09=9B)
    //              31 32 37 2e 30 2e 30 2e 31 (string="127.0.0.1")

    // 1: Use SDK PB and POST.
    // 2: Use new PB and SDK POST.
    // 3: Use new PB and POST.
    #define SWITCHER 3

    // Use SDK PB and POST.
#if SWITCHER == 1
    cls::LogGroup loggroup;
    loggroup.set_source("127.0.0.1");
    auto log = loggroup.add_logs();
    log->set_time(now);
    auto content = log->add_contents();
    content->set_key("content"); content->set_value("this my test log");
    auto content2 = log->add_contents();
    content2->set_key("version"); content2->set_value("v5.0.35");
    auto content3 = log->add_contents();
    content3->set_key("region"); content3->set_value("cn");

    PostLogStoreLogsResponse ret;
    try {
        for (int i = 0; i < 1; ++i) {
            ret = ptr->PostLogStoreLogs(topic, loggroup);
            printf("%s\n", ret.Printf().c_str());
        }
    }
    catch (LOGException &e) {
        cout << e.GetErrorCode() << ":" << e.GetMessage() << endl;
    }

#elif SWITCHER == 2
    // Use new PB and SDK POST.
    SrsClsLogGroupList loggroup;
    SrsClsLog* log = loggroup.add_log_group()->set_source("127.0.0.1")->add_log()->set_time(now);
    log->add_content()->set_key("content")->set_value("this my test log");
    log->add_content()->set_key("version")->set_value("v5.0.35");
    log->add_content()->set_key("region")->set_value("cn");

    PostLogStoreLogsResponse ret;
    try {
        for (int i = 0; i < 1; ++i) {
            int size = loggroup.nb_bytes();
            char buf[size];
            memset(buf, 0, size);
            SrsBuffer b(buf, size);
            if (loggroup.encode(&b)) {
                printf("encode log failed");
                exit(-1);
            }
            ret = ptr->PostLogStoreLogs2(topic, string(buf, size));
            printf("%s\n", ret.Printf().c_str());
        }
    } catch (LOGException &e) {
        cout << e.GetErrorCode() << ":" << e.GetMessage() << endl;
    }

#elif SWITCHER == 3
    // Use new PB and POST.
    SrsClsLogGroupList loggroup;
    SrsClsLog* log = loggroup.add_log_group()->set_source("127.0.0.1")->add_log()->set_time(now);
    log->add_content()->set_key("content")->set_value("this my test log");
    log->add_content()->set_key("version")->set_value("v5.0.35");
    log->add_content()->set_key("region")->set_value("cn");

    PostLogStoreLogsResponse ret;
    try {
        for (int i = 0; i < 1; ++i) {
            int size = loggroup.nb_bytes();
            char buf[size];
            memset(buf, 0, size);
            SrsBuffer b(buf, size);
            if (loggroup.encode(&b)) {
                printf("encode log failed");
                exit(-1);
            }
            ret = send_logs(topic, string(buf, size), endpoint, ak_id, ak_secret);
            printf("%s\n", ret.Printf().c_str());
        }
    } catch (LOGException &e) {
        cout << e.GetErrorCode() << ":" << e.GetMessage() << endl;
    }
#endif

    return 0;
}

