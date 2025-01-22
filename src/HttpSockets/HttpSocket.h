#pragma

#define SSL_MAX_RECORD_SIZE 16384
#include <string>
#include <memory>
#include <openssl/ssl.h>
#include <openssl/err.h>


void openssl_error_stack_bt(FILE* fp);
void openssl_discard_error(SSL *ssl, int ret);
int openssl_get_error_reason(unsigned long error);

// Custom deleters for OpenSSL objects
struct SSLDeleter {
    void operator()(SSL* ssl) const {
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            ssl = nullptr;
        }
    }
};

struct SSL_CTX_Deleter {
    void operator()(SSL_CTX* ctx) const {
        if (ctx) {
            SSL_CTX_free(ctx);
            ctx = nullptr;
        }
    }
};

class HttpSocket{
public:
    ~HttpSocket();
    HttpSocket();

    bool Connect(std::string& hostname, int port);

    int Send(const char *payload, int size);

    int Read(char *out, int size);

    bool Close(char* out, int size);

private:
    int sock;
    std::unique_ptr<SSL_CTX, SSL_CTX_Deleter> ctx;
    std::unique_ptr<SSL, SSLDeleter> ssl;
};
