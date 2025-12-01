#include <iostream>
#include <string>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>

using namespace std;

class SSLHelper
{
public:
    string username = "";
    const char *CERT_FILE = "cert.pem";
    const char *KEY_FILE = "key.pem";
    const char *CA_FILE = "ca.pem";
    SSL_CTX *ssl_context = nullptr;
    SSL *peerSSL = nullptr; // TLS object for the current peer socket

    SSLHelper(const std::string &username) {
        this->username = username;
        // Remove existing keys
        std::string rmdir_cmd = "rm -rf " + username; // -p avoids error if exists
        if (system(rmdir_cmd.c_str()) != 0)
        {
            std::cerr << "Failed to remove directory\n";
            return;
        }
        // Create directory
        std::string mkdir_cmd = "mkdir -p " + username; // -p avoids error if exists
        if (system(mkdir_cmd.c_str()) != 0)
        {
            std::cerr << "Failed to create directory\n";
            return;
        }

        // Generate private key in that directory
        std::string key_cmd = "openssl genrsa -out " + username + "/server.key 2048";
        if (system(key_cmd.c_str()) != 0)
        {
            std::cerr << "Failed to generate key\n";
            return;
        }

        std::string subject = "/C=US/ST=WA/L=Pullman/O=MyOrg/OU=Server/CN=" + username;
        std::string private_cmd = "openssl req -new -x509 -key " + username + "/server.key -out " + username + "/server.crt -days 365 -subj \"" + subject + "\"";
        if (system(private_cmd.c_str()) != 0)
        {
            std::cerr << "Failed to generate private key\n";
            return;
        }

        std::cout << "Directory and key created successfully.\n";
        return;
    }

    void init_openssl()
    {
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
    }

    void cleanup_openssl()
    {
        if (ssl_context)
        {
            SSL_CTX_free(ssl_context);
            ssl_context = nullptr;
        }
        ERR_free_strings();
        EVP_cleanup();
    }

    SSL_CTX *create_context()
    {
        const SSL_METHOD *method = TLS_method();
        SSL_CTX *ctx = SSL_CTX_new(method);
        if (!ctx)
        {
            cerr << "Unable to create SSL context" << endl;
            ERR_print_errors_fp(stderr);
            return nullptr;
        }

        /* Set recommended options: */
        SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);
        this->ssl_context = ctx;
        return ctx;
    }

    bool load_certificates(SSL_CTX *ctx, const char *cert_file, const char *key_file, const char *ca_file)
    {
        if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0)
        {
            cerr << "Error loading certificate from " << cert_file << endl;
            ERR_print_errors_fp(stderr);
            return false;
        }
        if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0)
        {
            cerr << "Error loading private key from " << key_file << endl;
            ERR_print_errors_fp(stderr);
            return false;
        }
        if (!SSL_CTX_check_private_key(ctx))
        {
            cerr << "Private key does not match the public certificate\n";
            return false;
        }

        // // Load CA to verify peer certificates (optional for client verification / mutual TLS)
        // if (CA_FILE)
        // {
        //     if (!SSL_CTX_load_verify_locations(ctx, ca_file, NULL))
        //     {
        //         cerr << "Warning: could not load CA file: " << ca_file << " — continuing without CA verification.\n";
        //         // Not fatal for now — but you should have CA in production.
        //     }
        //     else
        //     {
        //         // require peer verification if you want mutual TLS:
        //         SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        //         SSL_CTX_set_verify_depth(ctx, 4);
        //     }
        // }

        return true;
    }

    /* Wrap accepted socket into an SSL object and perform server handshake */
    SSL *tls_server_handshake(int fd)
    {
        SSL *ssl = SSL_new(ssl_context);
        if (!ssl)
        {
            ERR_print_errors_fp(stderr);
            return nullptr;
        }
        SSL_set_fd(ssl, fd);

        int r = SSL_accept(ssl);
        if (r <= 0)
        {
            int err = SSL_get_error(ssl, r);
            cerr << "SSL_accept failed: " << err << endl;
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            return nullptr;
        }
        // Optionally inspect client cert:
        X509 *peer_cert = SSL_get_peer_certificate(ssl);
        if (peer_cert)
        {
            // You could extract CN and verify it's an allowed peer
            X509_free(peer_cert);
        }
        this->peerSSL = ssl;
        return ssl;
    }

    /* Create SSL and do client handshake on a connected socket */
    SSL *tls_client_handshake(int fd)
    {
        SSL *ssl = SSL_new(ssl_context);
        if (!ssl)
        {
            ERR_print_errors_fp(stderr);
            return nullptr;
        }
        SSL_set_fd(ssl, fd);

        int r = SSL_connect(ssl);
        if (r <= 0)
        {
            int err = SSL_get_error(ssl, r);
            cerr << "SSL_connect failed: " << err << endl;
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            return nullptr;
        }

        this->peerSSL = ssl;
        return ssl;
    }

    /* Convenience send/recv that use TLS if peerSSL is set */
    ssize_t ssl_send(const void *buf, size_t len, int peerSockFD)
    {
        if (peerSSL)
        {
            int r = SSL_write(peerSSL, buf, (int)len);
            if (r <= 0)
            {
                int err = SSL_get_error(peerSSL, r);
                cerr << "SSL_write error: " << err << endl;
                return -1;
            }
            return r;
        }
        else
        {
            return send(peerSockFD, buf, len, 0);
        }
    }

    ssize_t ssl_recv(void *buf, size_t len, int peerSockFD)
    {
        if (peerSSL)
        {
            int r = SSL_read(peerSSL, buf, (int)len);
            if (r <= 0)
            {
                int err = SSL_get_error(peerSSL, r);
                if (err == SSL_ERROR_ZERO_RETURN)
                {
                    // TLS connection closed cleanly
                    return 0;
                }
                cerr << "SSL_read error: " << err << endl;
                return -1;
            }
            return r;
        }
        else
        {
            return recv(peerSockFD, buf, len, 0);
        }
    }
};
