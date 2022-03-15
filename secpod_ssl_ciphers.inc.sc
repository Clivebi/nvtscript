var sslv2_ciphers, sslv3_tls_ciphers;
sslv2_ciphers["SSL2_RC4_128_WITH_MD5 : Weak cipher"] = raw_string( 0x01, 0x00, 0x80 );
sslv2_ciphers["SSL2_RC4_128_EXPORT40_WITH_MD5 : Weak cipher"] = raw_string( 0x02, 0x00, 0x80 );
sslv2_ciphers["SSL2_RC2_CBC_128_CBC_WITH_MD5 : Weak cipher"] = raw_string( 0x03, 0x00, 0x80 );
sslv2_ciphers["SSL2_RC2_CBC_128_CBC_EXPORT40_WITH_MD5 : Weak cipher"] = raw_string( 0x04, 0x00, 0x80 );
sslv2_ciphers["SSL2_IDEA_128_CBC_WITH_MD5 : Weak cipher"] = raw_string( 0x05, 0x00, 0x80 );
sslv2_ciphers["SSL2_DES_64_CBC_WITH_MD5 : Weak cipher"] = raw_string( 0x06, 0x00, 0x40 );
sslv2_ciphers["SSL2_DES_192_EDE3_CBC_WITH_MD5 : Weak cipher"] = raw_string( 0x07, 0x00, 0xc0 );
sslv2_ciphers["SSL2_NULL : Null cipher"] = raw_string( 0xff, 0x08, 0x10 );
sslv2_ciphers["SSL2_NULL_WITH_MD5 : Null cipher"] = raw_string( 0x00, 0x00, 0x00 );
sslv2_ciphers["SSL2_DES_192_EDE3_CBC_WITH_SHA : Weak cipher"] = raw_string( 0x07, 0x01, 0xc0 );
sslv2_ciphers["SSL2_RC4_64_WITH_MD5 : Weak cipher"] = raw_string( 0x08, 0x00, 0x80 );
sslv2_ciphers["SSL2_DES_64_CBC_WITH_SHA : Weak cipher"] = raw_string( 0x06, 0x01, 0x40 );
sslv2_ciphers["SSL2_DES_64_CFB64_WITH_MD5_1 : Weak cipher"] = raw_string( 0xff, 0x08, 0x00 );
sslv2_ciphers["SSL2_UNKNOWN : Weak cipher"] = raw_string( 0x06, 0x00, 0x80 );
sslv3_tls_ciphers["TLS_NULL_WITH_NULL_NULL : Null cipher, no authentication"] = raw_string( 0x00, 0x00 );
sslv3_tls_ciphers["TLS_RSA_WITH_NULL_MD5 : Null cipher"] = raw_string( 0x00, 0x01 );
sslv3_tls_ciphers["TLS_RSA_WITH_NULL_SHA : Null cipher"] = raw_string( 0x00, 0x02 );
sslv3_tls_ciphers["TLS_RSA_EXPORT_WITH_RC4_40_MD5 : Weak cipher"] = raw_string( 0x00, 0x03 );
sslv3_tls_ciphers["TLS_RSA_WITH_RC4_128_MD5 : Weak cipher"] = raw_string( 0x00, 0x04 );
sslv3_tls_ciphers["TLS_RSA_WITH_RC4_128_SHA : Weak cipher"] = raw_string( 0x00, 0x05 );
sslv3_tls_ciphers["TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 : Weak cipher"] = raw_string( 0x00, 0x06 );
sslv3_tls_ciphers["TLS_RSA_WITH_IDEA_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x07 );
sslv3_tls_ciphers["TLS_RSA_EXPORT_WITH_DES40_CBC_SHA : Weak cipher"] = raw_string( 0x00, 0x08 );
sslv3_tls_ciphers["TLS_RSA_WITH_DES_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x09 );
sslv3_tls_ciphers["TLS_RSA_WITH_3DES_EDE_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x0A );
sslv3_tls_ciphers["TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA : Weak cipher"] = raw_string( 0x00, 0x0B );
sslv3_tls_ciphers["TLS_DH_DSS_WITH_DES_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x0C );
sslv3_tls_ciphers["TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x0D );
sslv3_tls_ciphers["TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA : Weak cipher"] = raw_string( 0x00, 0x0E );
sslv3_tls_ciphers["TLS_DH_RSA_WITH_DES_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x0F );
sslv3_tls_ciphers["TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x10 );
sslv3_tls_ciphers["TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA : Weak cipher"] = raw_string( 0x00, 0x11 );
sslv3_tls_ciphers["TLS_DHE_DSS_WITH_DES_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x12 );
sslv3_tls_ciphers["TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x13 );
sslv3_tls_ciphers["TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA : Weak cipher"] = raw_string( 0x00, 0x14 );
sslv3_tls_ciphers["TLS_DHE_RSA_WITH_DES_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x15 );
sslv3_tls_ciphers["TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x16 );
sslv3_tls_ciphers["TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 : Weak cipher"] = raw_string( 0x00, 0x17 );
sslv3_tls_ciphers["TLS_DH_anon_WITH_RC4_128_MD5 : Weak cipher"] = raw_string( 0x00, 0x18 );
sslv3_tls_ciphers["TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA : Weak cipher"] = raw_string( 0x00, 0x19 );
sslv3_tls_ciphers["TLS_DH_anon_WITH_DES_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x1A );
sslv3_tls_ciphers["TLS_DH_anon_WITH_3DES_EDE_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x1B );
sslv3_tls_ciphers["TLS_FORTEZZA_KEA_WITH_NULL_SHA : Null cipher"] = raw_string( 0x00, 0x1C );
sslv3_tls_ciphers["TLS_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA : Weak cipher"] = raw_string( 0x00, 0x1D );
sslv3_tls_ciphers["TLS_FORTEZZA_KEA_WITH_RC4_128_SHA or TLS_KRB5_WITH_DES_CBC_SHA : Weak cipher"] = raw_string( 0x00, 0x1E );
sslv3_tls_ciphers["TLS_KRB5_WITH_3DES_EDE_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x1F );
sslv3_tls_ciphers["TLS_KRB5_WITH_RC4_128_SHA : Weak cipher"] = raw_string( 0x00, 0x20 );
sslv3_tls_ciphers["TLS_KRB5_WITH_IDEA_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x21 );
sslv3_tls_ciphers["TLS_KRB5_WITH_DES_CBC_MD5 : Medium cipher"] = raw_string( 0x00, 0x22 );
sslv3_tls_ciphers["TLS_KRB5_WITH_3DES_EDE_CBC_MD5 : Medium cipher"] = raw_string( 0x00, 0x23 );
sslv3_tls_ciphers["TLS_KRB5_WITH_RC4_128_MD5 : Weak cipher"] = raw_string( 0x00, 0x24 );
sslv3_tls_ciphers["TLS_KRB5_WITH_IDEA_CBC_MD5 : Medium cipher"] = raw_string( 0x00, 0x25 );
sslv3_tls_ciphers["TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA : Weak cipher"] = raw_string( 0x00, 0x26 );
sslv3_tls_ciphers["TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA : Weak cipher"] = raw_string( 0x00, 0x27 );
sslv3_tls_ciphers["TLS_KRB5_EXPORT_WITH_RC4_40_SHA : Weak cipher"] = raw_string( 0x00, 0x28 );
sslv3_tls_ciphers["TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5 : Weak cipher"] = raw_string( 0x00, 0x29 );
sslv3_tls_ciphers["TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5 : Weak cipher"] = raw_string( 0x00, 0x2A );
sslv3_tls_ciphers["TLS_KRB5_EXPORT_WITH_RC4_40_MD5 : Weak cipher"] = raw_string( 0x00, 0x2B );
sslv3_tls_ciphers["TLS_PSK_WITH_NULL_SHA : Null cipher"] = raw_string( 0x00, 0x2C );
sslv3_tls_ciphers["TLS_DHE_PSK_WITH_NULL_SHA : Null cipher"] = raw_string( 0x00, 0x2D );
sslv3_tls_ciphers["TLS_RSA_PSK_WITH_NULL_SHA : Null cipher"] = raw_string( 0x00, 0x2E );
sslv3_tls_ciphers["TLS_RSA_WITH_AES_128_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x2F );
sslv3_tls_ciphers["TLS_DH_DSS_WITH_AES_128_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x30 );
sslv3_tls_ciphers["TLS_DH_RSA_WITH_AES_128_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x31 );
sslv3_tls_ciphers["TLS_DHE_DSS_WITH_AES_128_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x32 );
sslv3_tls_ciphers["TLS_DHE_RSA_WITH_AES_128_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x33 );
sslv3_tls_ciphers["TLS_DH_anon_WITH_AES_128_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x34 );
sslv3_tls_ciphers["TLS_RSA_WITH_AES_256_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x35 );
sslv3_tls_ciphers["TLS_DH_DSS_WITH_AES_256_CBC_SHA : Strong cipher"] = raw_string( 0x00, 0x36 );
sslv3_tls_ciphers["TLS_DH_RSA_WITH_AES_256_CBC_SHA : Strong cipher"] = raw_string( 0x00, 0x37 );
sslv3_tls_ciphers["TLS_DHE_DSS_WITH_AES_256_CBC_SHA : Strong cipher"] = raw_string( 0x00, 0x38 );
sslv3_tls_ciphers["TLS_DHE_RSA_WITH_AES_256_CBC_SHA : Strong cipher"] = raw_string( 0x00, 0x39 );
sslv3_tls_ciphers["TLS_DH_anon_WITH_AES_256_CBC_SHA : Strong cipher"] = raw_string( 0x00, 0x3A );
sslv3_tls_ciphers["TLS_RSA_WITH_NULL_SHA256 : Null cipher"] = raw_string( 0x00, 0x3B );
sslv3_tls_ciphers["TLS_RSA_WITH_AES_128_CBC_SHA256 : Medium cipher"] = raw_string( 0x00, 0x3C );
sslv3_tls_ciphers["TLS_RSA_WITH_AES_256_CBC_SHA256 : Medium cipher"] = raw_string( 0x00, 0x3D );
sslv3_tls_ciphers["TLS_DH_DSS_WITH_AES_128_CBC_SHA256 : Medium cipher"] = raw_string( 0x00, 0x3E );
sslv3_tls_ciphers["TLS_DH_RSA_WITH_AES_128_CBC_SHA256 : Medium cipher"] = raw_string( 0x00, 0x3F );
sslv3_tls_ciphers["TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 : Medium cipher"] = raw_string( 0x00, 0x40 );
sslv3_tls_ciphers["TLS_RSA_WITH_CAMELLIA_128_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x41 );
sslv3_tls_ciphers["TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x42 );
sslv3_tls_ciphers["TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x43 );
sslv3_tls_ciphers["TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x44 );
sslv3_tls_ciphers["TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x45 );
sslv3_tls_ciphers["TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x46 );
sslv3_tls_ciphers["TLS_ECDH_ECDSA_WITH_NULL_SHA (Draft) : Null cipher"] = raw_string( 0x00, 0x47 );
sslv3_tls_ciphers["TLS_ECDH_ECDSA_WITH_RC4_128_SHA (Draft) : Weak cipher"] = raw_string( 0x00, 0x48 );
sslv3_tls_ciphers["TLS_ECDH_ECDSA_WITH_DES_CBC_SHA (Draft) : Medium cipher"] = raw_string( 0x00, 0x49 );
sslv3_tls_ciphers["TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA (Draft) : Medium cipher"] = raw_string( 0x00, 0x4A );
sslv3_tls_ciphers["TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA (Draft) or TLS_ECDH_ECDSA_EXPORT_WITH_RC4_40_SHA (Draft) : Weak cipher"] = raw_string( 0x00, 0x4B );
sslv3_tls_ciphers["TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA (Draft) or TLS_ECDH_ECDSA_EXPORT_WITH_RC4_56_SHA (Draft) : Weak cipher"] = raw_string( 0x00, 0x4C );
sslv3_tls_ciphers["TLS_ECDH_RSA_WITH_NULL_SHA (Draft) : Null cipher"] = raw_string( 0x00, 0x4D );
sslv3_tls_ciphers["TLS_ECDH_RSA_WITH_RC4_128_SHA (Draft) : Weak cipher"] = raw_string( 0x00, 0x4E );
sslv3_tls_ciphers["TLS_ECDH_RSA_WITH_DES_CBC_SHA (Draft) : Medium cipher"] = raw_string( 0x00, 0x4F );
sslv3_tls_ciphers["TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA (Draft) or TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA (Draft) : Medium cipher"] = raw_string( 0x00, 0x50 );
sslv3_tls_ciphers["TLS_ECDH_RSA_WITH_AES_128_CBC_SHA (Draft) or TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA (Draft) : Medium cipher"] = raw_string( 0x00, 0x51 );
sslv3_tls_ciphers["TLS_ECDH_RSA_WITH_AES_256_CBC_SHA (Draft) or TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA (Draft) : Medium cipher"] = raw_string( 0x00, 0x52 );
sslv3_tls_ciphers["TLS_ECDH_RSA_EXPORT_WITH_RC4_40_SHA (Draft) or TLS_SRP_SHA_WITH_AES_128_CBC_SHA (Draft) : Weak cipher"] = raw_string( 0x00, 0x53 );
sslv3_tls_ciphers["TLS_ECDH_RSA_EXPORT_WITH_RC4_56_SHA (Draft) or TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA (Draft) : Weak cipher"] = raw_string( 0x00, 0x54 );
sslv3_tls_ciphers["TLS_ECDH_anon_NULL_WITH_SHA (Draft) or TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA (Draft) : Null cipher"] = raw_string( 0x00, 0x55 );
sslv3_tls_ciphers["TLS_ECDH_anon_WITH_RC4_128_SHA (Draft) or TLS_SRP_SHA_WITH_AES_256_CBC_SHA (Draft) : Weak cipher"] = raw_string( 0x00, 0x56 );
sslv3_tls_ciphers["TLS_ECDH_anon_WITH_DES_CBC_SHA (Draft) or TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA (Draft) : Medium cipher"] = raw_string( 0x00, 0x57 );
sslv3_tls_ciphers["TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA (Draft) or TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA (Draft) : Medium cipher"] = raw_string( 0x00, 0x58 );
sslv3_tls_ciphers["TLS_ECDH_anon_EXPORT_WITH_DES40_CBC_SHA (Draft1) : Weak cipher"] = raw_string( 0x00, 0x59 );
sslv3_tls_ciphers["TLS_ECDH_anon_EXPORT_WITH_RC4_40_SHA (Draft1) : Weak cipher"] = raw_string( 0x00, 0x5A );
sslv3_tls_ciphers["TLS_ECDH_anon_EXPORT_WITH_DES40_CBC_SHA (Draft2) : Weak cipher"] = raw_string( 0x00, 0x5B );
sslv3_tls_ciphers["TLS_ECDH_anon_EXPORT_WITH_RC4_40_SHA (Draft2) : Weak cipher"] = raw_string( 0x00, 0x5C );
sslv3_tls_ciphers["TLS_RSA_EXPORT1024_WITH_RC4_56_MD5 : Weak cipher, weak authentication"] = raw_string( 0x00, 0x60 );
sslv3_tls_ciphers["TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5 : Weak cipher, weak authentication"] = raw_string( 0x00, 0x61 );
sslv3_tls_ciphers["TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA : Weak cipher, weak authentication"] = raw_string( 0x00, 0x62 );
sslv3_tls_ciphers["TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA : Weak cipher, weak authentication"] = raw_string( 0x00, 0x63 );
sslv3_tls_ciphers["TLS_RSA_EXPORT1024_WITH_RC4_56_SHA : Weak cipher, weak authentication"] = raw_string( 0x00, 0x64 );
sslv3_tls_ciphers["TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA : Weak cipher, weak authentication"] = raw_string( 0x00, 0x65 );
sslv3_tls_ciphers["TLS_DHE_DSS_WITH_RC4_128_SHA : Weak cipher"] = raw_string( 0x00, 0x66 );
sslv3_tls_ciphers["TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 : Medium cipher"] = raw_string( 0x00, 0x67 );
sslv3_tls_ciphers["TLS_DH_DSS_WITH_AES_256_CBC_SHA256 : Medium cipher"] = raw_string( 0x00, 0x68 );
sslv3_tls_ciphers["TLS_DH_RSA_WITH_AES_256_CBC_SHA256 : Medium cipher"] = raw_string( 0x00, 0x69 );
sslv3_tls_ciphers["TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 : Medium cipher"] = raw_string( 0x00, 0x6A );
sslv3_tls_ciphers["TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 : Medium cipher"] = raw_string( 0x00, 0x6B );
sslv3_tls_ciphers["TLS_DH_anon_WITH_AES_128_CBC_SHA256 : Medium cipher"] = raw_string( 0x00, 0x6C );
sslv3_tls_ciphers["TLS_DH_anon_WITH_AES_256_CBC_SHA256 : Medium cipher"] = raw_string( 0x00, 0x6D );
sslv3_tls_ciphers["TLS_KRB5_WITH_3DES_EDE_CBC_SHA (Draft) : Medium cipher"] = raw_string( 0x00, 0x70 );
sslv3_tls_ciphers["TLS_KRB5_WITH_3DES_EDE_CBC_MD5 (Draft) : Medium cipher"] = raw_string( 0x00, 0x71 );
sslv3_tls_ciphers["TLS_KRB5_WITH_RC4_128_SHA (Draft) : Weak cipher"] = raw_string( 0x00, 0x72 );
sslv3_tls_ciphers["TLS_KRB5_WITH_RC4_128_MD5 (Draft) : Weak cipher"] = raw_string( 0x00, 0x73 );
sslv3_tls_ciphers["TLS_KRB5_WITH_DES_CBC_SHA (Draft) : Medium cipher"] = raw_string( 0x00, 0x74 );
sslv3_tls_ciphers["TLS_KRB5_WITH_DES_CBC_MD5 (Draft) : Medium cipher"] = raw_string( 0x00, 0x75 );
sslv3_tls_ciphers["TLS_KRB5_WITH_AES_128_CBC_SHA (Draft) : Weak cipher"] = raw_string( 0x00, 0x76 );
sslv3_tls_ciphers["TLS_KRB5_WITH_AES_256_CBC_SHA (Draft) : Weak cipher"] = raw_string( 0x00, 0x77 );
sslv3_tls_ciphers["TLS_KRB5_WITH_NULL_SHA (Draft) : Null cipher"] = raw_string( 0x00, 0x78 );
sslv3_tls_ciphers["TLS_KRB5_WITH_NULL_MD5 (Draft) : Null cipher"] = raw_string( 0x00, 0x79 );
sslv3_tls_ciphers["TLS_GOSTR341094_WITH_28147_CNT_IMIT (Draft) : Strong cipher"] = raw_string( 0x00, 0x80 );
sslv3_tls_ciphers["TLS_GOSTR341001_WITH_28147_CNT_IMIT (Draft) : Strong cipher"] = raw_string( 0x00, 0x81 );
sslv3_tls_ciphers["TLS_GOSTR341094_WITH_NULL_GOSTR3411 (Draft) : Null cipher"] = raw_string( 0x00, 0x82 );
sslv3_tls_ciphers["TLS_GOSTR341001_WITH_NULL_GOSTR3411 (Draft) : Null cipher"] = raw_string( 0x00, 0x83 );
sslv3_tls_ciphers["TLS_RSA_WITH_CAMELLIA_256_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x84 );
sslv3_tls_ciphers["TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x85 );
sslv3_tls_ciphers["TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x86 );
sslv3_tls_ciphers["TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x87 );
sslv3_tls_ciphers["TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x88 );
sslv3_tls_ciphers["TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x89 );
sslv3_tls_ciphers["TLS_PSK_WITH_RC4_128_SHA : Weak cipher"] = raw_string( 0x00, 0x8A );
sslv3_tls_ciphers["TLS_PSK_WITH_3DES_EDE_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x8B );
sslv3_tls_ciphers["TLS_PSK_WITH_AES_128_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x8C );
sslv3_tls_ciphers["TLS_PSK_WITH_AES_256_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x8D );
sslv3_tls_ciphers["TLS_DHE_PSK_WITH_RC4_128_SHA : Weak cipher"] = raw_string( 0x00, 0x8E );
sslv3_tls_ciphers["TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x8F );
sslv3_tls_ciphers["TLS_DHE_PSK_WITH_AES_128_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x90 );
sslv3_tls_ciphers["TLS_DHE_PSK_WITH_AES_256_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x91 );
sslv3_tls_ciphers["TLS_RSA_PSK_WITH_RC4_128_SHA : Weak cipher"] = raw_string( 0x00, 0x92 );
sslv3_tls_ciphers["TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x93 );
sslv3_tls_ciphers["TLS_RSA_PSK_WITH_AES_128_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x94 );
sslv3_tls_ciphers["TLS_RSA_PSK_WITH_AES_256_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x95 );
sslv3_tls_ciphers["TLS_RSA_WITH_SEED_CBC_SHA : Weak cipher"] = raw_string( 0x00, 0x96 );
sslv3_tls_ciphers["TLS_DH_DSS_WITH_SEED_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x97 );
sslv3_tls_ciphers["TLS_DH_RSA_WITH_SEED_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x98 );
sslv3_tls_ciphers["TLS_DHE_DSS_WITH_SEED_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x99 );
sslv3_tls_ciphers["TLS_DHE_RSA_WITH_SEED_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x9A );
sslv3_tls_ciphers["TLS_DH_anon_WITH_SEED_CBC_SHA : Medium cipher"] = raw_string( 0x00, 0x9B );
sslv3_tls_ciphers["TLS_RSA_WITH_AES_128_GCM_SHA256 : Medium cipher"] = raw_string( 0x00, 0x9C );
sslv3_tls_ciphers["TLS_RSA_WITH_AES_256_GCM_SHA384 : Medium cipher"] = raw_string( 0x00, 0x9D );
sslv3_tls_ciphers["TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 : Medium cipher"] = raw_string( 0x00, 0x9E );
sslv3_tls_ciphers["TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 : Medium cipher"] = raw_string( 0x00, 0x9F );
sslv3_tls_ciphers["TLS_DH_RSA_WITH_AES_128_GCM_SHA256 : Medium cipher"] = raw_string( 0x00, 0xA0 );
sslv3_tls_ciphers["TLS_DH_RSA_WITH_AES_256_GCM_SHA384 : Medium cipher"] = raw_string( 0x00, 0xA1 );
sslv3_tls_ciphers["TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 : Medium cipher"] = raw_string( 0x00, 0xA2 );
sslv3_tls_ciphers["TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 : Medium cipher"] = raw_string( 0x00, 0xA3 );
sslv3_tls_ciphers["TLS_DH_DSS_WITH_AES_128_GCM_SHA256 : Medium cipher"] = raw_string( 0x00, 0xA4 );
sslv3_tls_ciphers["TLS_DH_DSS_WITH_AES_256_GCM_SHA384 : Medium cipher"] = raw_string( 0x00, 0xA5 );
sslv3_tls_ciphers["TLS_DH_anon_WITH_AES_128_GCM_SHA256 : Medium cipher"] = raw_string( 0x00, 0xA6 );
sslv3_tls_ciphers["TLS_DH_anon_WITH_AES_256_GCM_SHA384 : Medium cipher"] = raw_string( 0x00, 0xA7 );
sslv3_tls_ciphers["TLS_PSK_WITH_AES_128_GCM_SHA256 : Medium cipher"] = raw_string( 0x00, 0xA8 );
sslv3_tls_ciphers["TLS_PSK_WITH_AES_256_GCM_SHA384 : Medium cipher"] = raw_string( 0x00, 0xA9 );
sslv3_tls_ciphers["TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 : Medium cipher"] = raw_string( 0x00, 0xAA );
sslv3_tls_ciphers["TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 : Medium cipher"] = raw_string( 0x00, 0xAB );
sslv3_tls_ciphers["TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 : Medium cipher"] = raw_string( 0x00, 0xAC );
sslv3_tls_ciphers["TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 : Medium cipher"] = raw_string( 0x00, 0xAD );
sslv3_tls_ciphers["TLS_PSK_WITH_AES_128_CBC_SHA256 : Medium cipher"] = raw_string( 0x00, 0xAE );
sslv3_tls_ciphers["TLS_PSK_WITH_AES_256_CBC_SHA384 : Medium cipher"] = raw_string( 0x00, 0xAF );
sslv3_tls_ciphers["TLS_PSK_WITH_NULL_SHA256 : Null cipher"] = raw_string( 0x00, 0xB0 );
sslv3_tls_ciphers["TLS_PSK_WITH_NULL_SHA384 : Null cipher"] = raw_string( 0x00, 0xB1 );
sslv3_tls_ciphers["TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 : Medium cipher"] = raw_string( 0x00, 0xB2 );
sslv3_tls_ciphers["TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 : Medium cipher"] = raw_string( 0x00, 0xB3 );
sslv3_tls_ciphers["TLS_DHE_PSK_WITH_NULL_SHA256 : Null cipher"] = raw_string( 0x00, 0xB4 );
sslv3_tls_ciphers["TLS_DHE_PSK_WITH_NULL_SHA384 : Null cipher"] = raw_string( 0x00, 0xB5 );
sslv3_tls_ciphers["TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 : Medium cipher"] = raw_string( 0x00, 0xB6 );
sslv3_tls_ciphers["TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 : Medium cipher"] = raw_string( 0x00, 0xB7 );
sslv3_tls_ciphers["TLS_RSA_PSK_WITH_NULL_SHA256 : Null cipher"] = raw_string( 0x00, 0xB8 );
sslv3_tls_ciphers["TLS_RSA_PSK_WITH_NULL_SHA384 : Null cipher"] = raw_string( 0x00, 0xB9 );
sslv3_tls_ciphers["TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 : Medium cipher"] = raw_string( 0x00, 0xBA );
sslv3_tls_ciphers["TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 : Medium cipher"] = raw_string( 0x00, 0xBB );
sslv3_tls_ciphers["TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 : Medium cipher"] = raw_string( 0x00, 0xBC );
sslv3_tls_ciphers["TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 : Medium cipher"] = raw_string( 0x00, 0xBD );
sslv3_tls_ciphers["TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 : Medium cipher"] = raw_string( 0x00, 0xBE );
sslv3_tls_ciphers["TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 : Medium cipher"] = raw_string( 0x00, 0xBF );
sslv3_tls_ciphers["TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 : Medium cipher"] = raw_string( 0x00, 0xC0 );
sslv3_tls_ciphers["TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 : Medium cipher"] = raw_string( 0x00, 0xC1 );
sslv3_tls_ciphers["TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 : Medium cipher"] = raw_string( 0x00, 0xC2 );
sslv3_tls_ciphers["TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 : Medium cipher"] = raw_string( 0x00, 0xC3 );
sslv3_tls_ciphers["TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 : Medium cipher"] = raw_string( 0x00, 0xC4 );
sslv3_tls_ciphers["TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 : Medium cipher"] = raw_string( 0x00, 0xC5 );
sslv3_tls_ciphers["TLS_AES_128_GCM_SHA256 : Medium cipher"] = raw_string( 0x13, 0x01 );
sslv3_tls_ciphers["TLS_AES_256_GCM_SHA384 : Strong cipher"] = raw_string( 0x13, 0x02 );
sslv3_tls_ciphers["TLS_CHACHA20_POLY1305_SHA256 : Strong cipher"] = raw_string( 0x13, 0x03 );
sslv3_tls_ciphers["TLS_AES_128_CCM_SHA256 : Medium cipher"] = raw_string( 0x13, 0x04 );
sslv3_tls_ciphers["TLS_AES_128_CCM_8_SHA256 : Medium cipher"] = raw_string( 0x13, 0x05 );
sslv3_tls_ciphers["TLS_ECDH_ECDSA_WITH_NULL_SHA : Null cipher"] = raw_string( 0xC0, 0x01 );
sslv3_tls_ciphers["TLS_ECDH_ECDSA_WITH_RC4_128_SHA : Weak cipher"] = raw_string( 0xC0, 0x02 );
sslv3_tls_ciphers["TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA : Medium cipher"] = raw_string( 0xC0, 0x03 );
sslv3_tls_ciphers["TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA : Medium cipher"] = raw_string( 0xC0, 0x04 );
sslv3_tls_ciphers["TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA : Medium cipher"] = raw_string( 0xC0, 0x05 );
sslv3_tls_ciphers["TLS_ECDHE_ECDSA_WITH_NULL_SHA : Null cipher"] = raw_string( 0xC0, 0x06 );
sslv3_tls_ciphers["TLS_ECDHE_ECDSA_WITH_RC4_128_SHA : Weak cipher"] = raw_string( 0xC0, 0x07 );
sslv3_tls_ciphers["TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA : Medium cipher"] = raw_string( 0xC0, 0x08 );
sslv3_tls_ciphers["TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA : Medium cipher"] = raw_string( 0xC0, 0x09 );
sslv3_tls_ciphers["TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA : Medium cipher"] = raw_string( 0xC0, 0x0A );
sslv3_tls_ciphers["TLS_ECDH_RSA_WITH_NULL_SHA : Null cipher"] = raw_string( 0xC0, 0x0B );
sslv3_tls_ciphers["TLS_ECDH_RSA_WITH_RC4_128_SHA : Weak cipher"] = raw_string( 0xC0, 0x0C );
sslv3_tls_ciphers["TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA : Medium cipher"] = raw_string( 0xC0, 0x0D );
sslv3_tls_ciphers["TLS_ECDH_RSA_WITH_AES_128_CBC_SHA : Medium cipher"] = raw_string( 0xC0, 0x0E );
sslv3_tls_ciphers["TLS_ECDH_RSA_WITH_AES_256_CBC_SHA : Medium cipher"] = raw_string( 0xC0, 0x0F );
sslv3_tls_ciphers["TLS_ECDHE_RSA_WITH_NULL_SHA : Null cipher"] = raw_string( 0xC0, 0x10 );
sslv3_tls_ciphers["TLS_ECDHE_RSA_WITH_RC4_128_SHA : Weak cipher"] = raw_string( 0xC0, 0x11 );
sslv3_tls_ciphers["TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA : Medium cipher"] = raw_string( 0xC0, 0x12 );
sslv3_tls_ciphers["TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA : Medium cipher"] = raw_string( 0xC0, 0x13 );
sslv3_tls_ciphers["TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA : Medium cipher"] = raw_string( 0xC0, 0x14 );
sslv3_tls_ciphers["TLS_ECDH_anon_WITH_NULL_SHA : Null cipher"] = raw_string( 0xC0, 0x15 );
sslv3_tls_ciphers["TLS_ECDH_anon_WITH_RC4_128_SHA : Weak cipher"] = raw_string( 0xC0, 0x16 );
sslv3_tls_ciphers["TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA : Medium cipher"] = raw_string( 0xC0, 0x17 );
sslv3_tls_ciphers["TLS_ECDH_anon_WITH_AES_128_CBC_SHA : Medium cipher"] = raw_string( 0xC0, 0x18 );
sslv3_tls_ciphers["TLS_ECDH_anon_WITH_AES_256_CBC_SHA : Medium cipher"] = raw_string( 0xC0, 0x19 );
sslv3_tls_ciphers["TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA : Medium cipher"] = raw_string( 0xC0, 0x1A );
sslv3_tls_ciphers["TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA : Medium cipher"] = raw_string( 0xC0, 0x1B );
sslv3_tls_ciphers["TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA : Medium cipher"] = raw_string( 0xC0, 0x1C );
sslv3_tls_ciphers["TLS_SRP_SHA_WITH_AES_128_CBC_SHA : Medium cipher"] = raw_string( 0xC0, 0x1D );
sslv3_tls_ciphers["TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA : Medium cipher"] = raw_string( 0xC0, 0x1E );
sslv3_tls_ciphers["TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA : Medium cipher"] = raw_string( 0xC0, 0x1F );
sslv3_tls_ciphers["TLS_SRP_SHA_WITH_AES_256_CBC_SHA : Medium cipher"] = raw_string( 0xC0, 0x20 );
sslv3_tls_ciphers["TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA : Medium cipher"] = raw_string( 0xC0, 0x21 );
sslv3_tls_ciphers["TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA : Medium cipher"] = raw_string( 0xC0, 0x22 );
sslv3_tls_ciphers["TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x23 );
sslv3_tls_ciphers["TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x24 );
sslv3_tls_ciphers["TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x25 );
sslv3_tls_ciphers["TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x26 );
sslv3_tls_ciphers["TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x27 );
sslv3_tls_ciphers["TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x28 );
sslv3_tls_ciphers["TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x29 );
sslv3_tls_ciphers["TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x2A );
sslv3_tls_ciphers["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x2B );
sslv3_tls_ciphers["TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x2C );
sslv3_tls_ciphers["TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x2D );
sslv3_tls_ciphers["TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x2E );
sslv3_tls_ciphers["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x2F );
sslv3_tls_ciphers["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x30 );
sslv3_tls_ciphers["TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x31 );
sslv3_tls_ciphers["TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x32 );
sslv3_tls_ciphers["TLS_ECDHE_PSK_WITH_RC4_128_SHA : Weak cipher"] = raw_string( 0xC0, 0x33 );
sslv3_tls_ciphers["TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA : Medium cipher"] = raw_string( 0xC0, 0x34 );
sslv3_tls_ciphers["TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA : Medium cipher"] = raw_string( 0xC0, 0x35 );
sslv3_tls_ciphers["TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA : Medium cipher"] = raw_string( 0xC0, 0x36 );
sslv3_tls_ciphers["TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x37 );
sslv3_tls_ciphers["TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x38 );
sslv3_tls_ciphers["TLS_ECDHE_PSK_WITH_NULL_SHA : Null cipher"] = raw_string( 0xC0, 0x39 );
sslv3_tls_ciphers["TLS_ECDHE_PSK_WITH_NULL_SHA256 : Null cipher"] = raw_string( 0xC0, 0x3A );
sslv3_tls_ciphers["TLS_ECDHE_PSK_WITH_NULL_SHA384 : Null cipher"] = raw_string( 0xC0, 0x3B );
sslv3_tls_ciphers["TLS_RSA_WITH_ARIA_128_CBC_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x3C );
sslv3_tls_ciphers["TLS_RSA_WITH_ARIA_256_CBC_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x3D );
sslv3_tls_ciphers["TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x3E );
sslv3_tls_ciphers["TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x3F );
sslv3_tls_ciphers["TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x40 );
sslv3_tls_ciphers["TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x41 );
sslv3_tls_ciphers["TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x42 );
sslv3_tls_ciphers["TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x43 );
sslv3_tls_ciphers["TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x44 );
sslv3_tls_ciphers["TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x45 );
sslv3_tls_ciphers["TLS_DH_anon_WITH_ARIA_128_CBC_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x46 );
sslv3_tls_ciphers["TLS_DH_anon_WITH_ARIA_256_CBC_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x47 );
sslv3_tls_ciphers["TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x48 );
sslv3_tls_ciphers["TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x49 );
sslv3_tls_ciphers["TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x4A );
sslv3_tls_ciphers["TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x4B );
sslv3_tls_ciphers["TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x4C );
sslv3_tls_ciphers["TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x4D );
sslv3_tls_ciphers["TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x4E );
sslv3_tls_ciphers["TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x4F );
sslv3_tls_ciphers["TLS_RSA_WITH_ARIA_128_GCM_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x50 );
sslv3_tls_ciphers["TLS_RSA_WITH_ARIA_256_GCM_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x51 );
sslv3_tls_ciphers["TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x52 );
sslv3_tls_ciphers["TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x53 );
sslv3_tls_ciphers["TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x54 );
sslv3_tls_ciphers["TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x55 );
sslv3_tls_ciphers["TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x56 );
sslv3_tls_ciphers["TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x57 );
sslv3_tls_ciphers["TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x58 );
sslv3_tls_ciphers["TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x59 );
sslv3_tls_ciphers["TLS_DH_anon_WITH_ARIA_128_GCM_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x5A );
sslv3_tls_ciphers["TLS_DH_anon_WITH_ARIA_256_GCM_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x5B );
sslv3_tls_ciphers["TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x5C );
sslv3_tls_ciphers["TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x5D );
sslv3_tls_ciphers["TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x5E );
sslv3_tls_ciphers["TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x5F );
sslv3_tls_ciphers["TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x60 );
sslv3_tls_ciphers["TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x61 );
sslv3_tls_ciphers["TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x62 );
sslv3_tls_ciphers["TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x63 );
sslv3_tls_ciphers["TLS_PSK_WITH_ARIA_128_CBC_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x64 );
sslv3_tls_ciphers["TLS_PSK_WITH_ARIA_256_CBC_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x65 );
sslv3_tls_ciphers["TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x66 );
sslv3_tls_ciphers["TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x67 );
sslv3_tls_ciphers["TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x68 );
sslv3_tls_ciphers["TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x69 );
sslv3_tls_ciphers["TLS_PSK_WITH_ARIA_128_GCM_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x6A );
sslv3_tls_ciphers["TLS_PSK_WITH_ARIA_256_GCM_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x6B );
sslv3_tls_ciphers["TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x6C );
sslv3_tls_ciphers["TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x6D );
sslv3_tls_ciphers["TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x6E );
sslv3_tls_ciphers["TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x6F );
sslv3_tls_ciphers["TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x70 );
sslv3_tls_ciphers["TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x71 );
sslv3_tls_ciphers["TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x72 );
sslv3_tls_ciphers["TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x73 );
sslv3_tls_ciphers["TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x74 );
sslv3_tls_ciphers["TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x75 );
sslv3_tls_ciphers["TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x76 );
sslv3_tls_ciphers["TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x77 );
sslv3_tls_ciphers["TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x78 );
sslv3_tls_ciphers["TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x79 );
sslv3_tls_ciphers["TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x7A );
sslv3_tls_ciphers["TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x7B );
sslv3_tls_ciphers["TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x7C );
sslv3_tls_ciphers["TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x7D );
sslv3_tls_ciphers["TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x7E );
sslv3_tls_ciphers["TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x7F );
sslv3_tls_ciphers["TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x80 );
sslv3_tls_ciphers["TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x81 );
sslv3_tls_ciphers["TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x82 );
sslv3_tls_ciphers["TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x83 );
sslv3_tls_ciphers["TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x84 );
sslv3_tls_ciphers["TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x85 );
sslv3_tls_ciphers["TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x86 );
sslv3_tls_ciphers["TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x87 );
sslv3_tls_ciphers["TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x88 );
sslv3_tls_ciphers["TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x89 );
sslv3_tls_ciphers["TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x8A );
sslv3_tls_ciphers["TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x8B );
sslv3_tls_ciphers["TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x8C );
sslv3_tls_ciphers["TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x8D );
sslv3_tls_ciphers["TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x8E );
sslv3_tls_ciphers["TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x8F );
sslv3_tls_ciphers["TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x90 );
sslv3_tls_ciphers["TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x91 );
sslv3_tls_ciphers["TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x92 );
sslv3_tls_ciphers["TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x93 );
sslv3_tls_ciphers["TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x94 );
sslv3_tls_ciphers["TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x95 );
sslv3_tls_ciphers["TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x96 );
sslv3_tls_ciphers["TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x97 );
sslv3_tls_ciphers["TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x98 );
sslv3_tls_ciphers["TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x99 );
sslv3_tls_ciphers["TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 : Medium cipher"] = raw_string( 0xC0, 0x9A );
sslv3_tls_ciphers["TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 : Medium cipher"] = raw_string( 0xC0, 0x9B );
sslv3_tls_ciphers["TLS_RSA_WITH_AES_128_CCM : Medium cipher"] = raw_string( 0xC0, 0x9C );
sslv3_tls_ciphers["TLS_RSA_WITH_AES_256_CCM : Medium cipher"] = raw_string( 0xC0, 0x9D );
sslv3_tls_ciphers["TLS_DHE_RSA_WITH_AES_128_CCM : Medium cipher"] = raw_string( 0xC0, 0x9E );
sslv3_tls_ciphers["TLS_DHE_RSA_WITH_AES_256_CCM : Medium cipher"] = raw_string( 0xC0, 0x9F );
sslv3_tls_ciphers["TLS_RSA_WITH_AES_128_CCM_8 : Medium cipher"] = raw_string( 0xC0, 0xA0 );
sslv3_tls_ciphers["TLS_RSA_WITH_AES_256_CCM_8 : Medium cipher"] = raw_string( 0xC0, 0xA1 );
sslv3_tls_ciphers["TLS_DHE_RSA_WITH_AES_128_CCM_8 : Medium cipher"] = raw_string( 0xC0, 0xA2 );
sslv3_tls_ciphers["TLS_DHE_RSA_WITH_AES_256_CCM_8 : Medium cipher"] = raw_string( 0xC0, 0xA3 );
sslv3_tls_ciphers["TLS_PSK_WITH_AES_128_CCM : Medium cipher"] = raw_string( 0xC0, 0xA4 );
sslv3_tls_ciphers["TLS_PSK_WITH_AES_256_CCM : Medium cipher"] = raw_string( 0xC0, 0xA5 );
sslv3_tls_ciphers["TLS_DHE_PSK_WITH_AES_128_CCM : Medium cipher"] = raw_string( 0xC0, 0xA6 );
sslv3_tls_ciphers["TLS_DHE_PSK_WITH_AES_256_CCM : Medium cipher"] = raw_string( 0xC0, 0xA7 );
sslv3_tls_ciphers["TLS_PSK_WITH_AES_128_CCM_8 : Medium cipher"] = raw_string( 0xC0, 0xA8 );
sslv3_tls_ciphers["TLS_PSK_WITH_AES_256_CCM_8 : Medium cipher"] = raw_string( 0xC0, 0xA9 );
sslv3_tls_ciphers["TLS_PSK_DHE_WITH_AES_128_CCM_8 : Medium cipher"] = raw_string( 0xC0, 0xAA );
sslv3_tls_ciphers["TLS_PSK_DHE_WITH_AES_256_CCM_8 : Medium cipher"] = raw_string( 0xC0, 0xAB );
sslv3_tls_ciphers["TLS_ECDHE_ECDSA_WITH_AES_128_CCM : Medium cipher"] = raw_string( 0xC0, 0xAC );
sslv3_tls_ciphers["TLS_ECDHE_ECDSA_WITH_AES_256_CCM : Medium cipher"] = raw_string( 0xC0, 0xAD );
sslv3_tls_ciphers["TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 : Medium cipher"] = raw_string( 0xC0, 0xAE );
sslv3_tls_ciphers["TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 : Medium cipher"] = raw_string( 0xC0, 0xAF );
sslv3_tls_ciphers["TLS_ECCPWD_WITH_AES_128_GCM_SHA256 (Draft) : Medium cipher"] = raw_string( 0xC0, 0xB0 );
sslv3_tls_ciphers["TLS_ECCPWD_WITH_AES_256_GCM_SHA384 (Draft) : Strong cipher"] = raw_string( 0xC0, 0xB1 );
sslv3_tls_ciphers["TLS_ECCPWD_WITH_AES_128_CCM_SHA256 (Draft) : Medium cipher"] = raw_string( 0xC0, 0xB2 );
sslv3_tls_ciphers["TLS_ECCPWD_WITH_AES_256_CCM_SHA384 (Draft) : Medium cipher"] = raw_string( 0xC0, 0xB3 );
sslv3_tls_ciphers["TLS_SHA256_SHA256 (Draft) : Weak cipher"] = raw_string( 0xC0, 0xB4 );
sslv3_tls_ciphers["TLS_SHA384_SHA384 (Draft) : Weak cipher"] = raw_string( 0xC0, 0xB5 );
sslv3_tls_ciphers["TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (Draft) : Strong cipher"] = raw_string( 0xCC, 0x13 );
sslv3_tls_ciphers["TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (Draft) : Strong cipher"] = raw_string( 0xCC, 0x14 );
sslv3_tls_ciphers["TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (Draft) : Strong cipher"] = raw_string( 0xCC, 0x15 );
sslv3_tls_ciphers["TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 : Strong cipher"] = raw_string( 0xCC, 0xA8 );
sslv3_tls_ciphers["TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 : Strong cipher"] = raw_string( 0xCC, 0xA9 );
sslv3_tls_ciphers["TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 : Strong cipher"] = raw_string( 0xCC, 0xAA );
sslv3_tls_ciphers["TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 : Strong cipher"] = raw_string( 0xCC, 0xAB );
sslv3_tls_ciphers["TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 : Strong cipher"] = raw_string( 0xCC, 0xAC );
sslv3_tls_ciphers["TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 : Strong cipher"] = raw_string( 0xCC, 0xAD );
sslv3_tls_ciphers["TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 : Strong cipher"] = raw_string( 0xCC, 0xAE );
sslv3_tls_ciphers["TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 : Medium cipher"] = raw_string( 0xD0, 0x01 );
sslv3_tls_ciphers["TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 : Strong cipher"] = raw_string( 0xD0, 0x01 );
sslv3_tls_ciphers["TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256 : Medium cipher"] = raw_string( 0xD0, 0x01 );
sslv3_tls_ciphers["TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256 : Medium cipher"] = raw_string( 0xD0, 0x01 );
sslv3_tls_ciphers["TLS_RSA_WITH_ESTREAM_SALSA20_SHA1 (Draft) : Medium cipher"] = raw_string( 0xE4, 0x10 );
sslv3_tls_ciphers["TLS_RSA_WITH_SALSA20_SHA1 (Draft) : Medium cipher"] = raw_string( 0xE4, 0x11 );
sslv3_tls_ciphers["TLS_ECDHE_RSA_WITH_ESTREAM_SALSA20_SHA1 (Draft) : Medium cipher"] = raw_string( 0xE4, 0x12 );
sslv3_tls_ciphers["TLS_ECDHE_RSA_WITH_SALSA20_SHA1 (Draft) : Medium cipher"] = raw_string( 0xE4, 0x13 );
sslv3_tls_ciphers["TLS_ECDHE_ECDSA_WITH_ESTREAM_SALSA20_SHA1 (Draft) : Medium cipher"] = raw_string( 0xE4, 0x14 );
sslv3_tls_ciphers["TLS_ECDHE_ECDSA_WITH_SALSA20_SHA1 (Draft) : Medium cipher"] = raw_string( 0xE4, 0x15 );
sslv3_tls_ciphers["TLS_PSK_WITH_ESTREAM_SALSA20_SHA1 (Draft) : Medium cipher"] = raw_string( 0xE4, 0x16 );
sslv3_tls_ciphers["TLS_PSK_WITH_SALSA20_SHA1 (Draft) : Medium cipher"] = raw_string( 0xE4, 0x17 );
sslv3_tls_ciphers["TLS_ECDHE_PSK_WITH_ESTREAM_SALSA20_SHA1 (Draft) : Medium cipher"] = raw_string( 0xE4, 0x18 );
sslv3_tls_ciphers["TLS_ECDHE_PSK_WITH_SALSA20_SHA1 (Draft) : Medium cipher"] = raw_string( 0xE4, 0x19 );
sslv3_tls_ciphers["TLS_RSA_PSK_WITH_ESTREAM_SALSA20_SHA1 (Draft) : Medium cipher"] = raw_string( 0xE4, 0x1A );
sslv3_tls_ciphers["TLS_RSA_PSK_WITH_SALSA20_SHA1 (Draft) : Medium cipher"] = raw_string( 0xE4, 0x1B );
sslv3_tls_ciphers["TLS_DHE_PSK_WITH_ESTREAM_SALSA20_SHA1 (Draft) : Medium cipher"] = raw_string( 0xE4, 0x1C );
sslv3_tls_ciphers["TLS_DHE_PSK_WITH_SALSA20_SHA1 (Draft) : Medium cipher"] = raw_string( 0xE4, 0x1D );
sslv3_tls_ciphers["TLS_DHE_RSA_WITH_ESTREAM_SALSA20_SHA1 (Draft) : Medium cipher"] = raw_string( 0xE4, 0x1E );
sslv3_tls_ciphers["TLS_DHE_RSA_WITH_SALSA20_SHA1 (Draft) : Medium cipher"] = raw_string( 0xE4, 0x1F );
sslv3_tls_ciphers["TLS_RSA_FIPS_WITH_DES_CBC_SHA (Draft) : Medium cipher"] = raw_string( 0xFE, 0xFE );
sslv3_tls_ciphers["TLS_RSA_FIPS_WITH_3DES_EDE_CBC_SHA (Draft) : Medium cipher"] = raw_string( 0xFE, 0xFF );
sslv3_tls_ciphers["TLS_RSA_FIPS_WITH_3DES_EDE_CBC_SHA_2 (Draft) : Medium cipher"] = raw_string( 0xFF, 0xE0 );
sslv3_tls_ciphers["TLS_RSA_FIPS_WITH_DES_CBC_SHA_2 (Draft) : Medium cipher"] = raw_string( 0xFF, 0xE1 );
sslv3_tls_ciphers["TLS_RSA_WITH_RC2_CBC_MD5 (Draft) : Weak cipher"] = raw_string( 0xFF, 0x80 );
sslv3_tls_ciphers["TLS_RSA_WITH_IDEA_CBC_MD5 (Draft) : Weak cipher"] = raw_string( 0xFF, 0x81 );
sslv3_tls_ciphers["TLS_RSA_WITH_DES_CBC_MD5 (Draft) : Medium cipher"] = raw_string( 0xFF, 0x82 );
sslv3_tls_ciphers["TLS_RSA_WITH_3DES_EDE_CBC_MD5 (Draft) : Medium cipher"] = raw_string( 0xFF, 0x83 );
SSL_v3 = raw_string( 0x03, 0x00 );
TLS_10 = raw_string( 0x03, 0x01 );
TLS_11 = raw_string( 0x03, 0x02 );
TLS_12 = raw_string( 0x03, 0x03 );
TLS_13 = raw_string( 0x03, 0x04 );
SSLv3_SERVER_HELLO = 2;
SSLv3_SERVER_HELLO_DONE = 14;
SSLv3_ALERT = 21;
func cipher_has_strength_override( cn ){
	var cn;
	var CIPHER_STRENGTH_OVERRIDE, old_cn_strength, old_cn_cs, co_strength, co_cs, CNO;
	if(isnull( cn ) || cn == ""){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#cn#-#cipher_has_strength_override" );
		return;
	}
	if(!CIPHER_STRENGTH_OVERRIDE = get_kb_item( "ssl/ciphers/override/" + cn )){
		return cn;
	}
	if(strlen( CIPHER_STRENGTH_OVERRIDE ) && !ContainsString( cn, CIPHER_STRENGTH_OVERRIDE )){
		old_cn_strength = eregmatch( pattern: "(Medium|Null|Weak|Strong) cipher", string: cn );
		if( !isnull( old_cn_strength[1] ) ) {
			old_cn_cs = old_cn_strength[1];
		}
		else {
			return cn;
		}
		co_strength = eregmatch( pattern: "(Medium|Null|Weak|Strong) cipher", string: CIPHER_STRENGTH_OVERRIDE );
		if( !isnull( co_strength[1] ) ) {
			co_cs = co_strength[1];
		}
		else {
			return cn;
		}
		if(co_cs == old_cn_cs){
			return cn;
		}
		CNO = ereg_replace( pattern: "(Medium|Null|Weak|Strong) cipher", replace: CIPHER_STRENGTH_OVERRIDE, string: cn );
		if(CNO && ContainsString( CNO, CIPHER_STRENGTH_OVERRIDE )){
			return CNO + " (custom override [" + old_cn_cs + " > " + co_cs + "])";
		}
	}
	return cn;
}
func report_cipher( cipher_name, port, ssl_ver ){
	var cipher_name, port, ssl_ver;
	var cipherName;
	if(!cipher_name){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#cipher_name#-#report_cipher" );
	}
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#report_cipher" );
	}
	if(!ssl_ver){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#ssl_ver#-#report_cipher" );
	}
	if(ContainsString( cipher_name, "Strong cipher" )){
		cipherName = ereg_replace( pattern: " :.*", string: cipher_name, replace: "" );
		set_kb_item( name: "secpod_ssl_ciphers/" + ssl_ver + "/" + port + "/supported_ciphers", value: cipherName );
		set_kb_item( name: "secpod_ssl_ciphers/" + ssl_ver + "/" + port + "/strong_ciphers", value: cipherName );
		set_kb_item( name: "secpod_ssl_ciphers/" + ssl_ver + "/" + port + "/nonweak_ciphers", value: cipherName );
		set_kb_item( name: "secpod_ssl_ciphers/supported_ciphers", value: TRUE );
		set_kb_item( name: "secpod_ssl_ciphers/nonweak_ciphers", value: TRUE );
		set_kb_item( name: "secpod_ssl_ciphers/strong_ciphers", value: TRUE );
	}
	if(ContainsString( cipher_name, "Medium cipher" )){
		cipherName = ereg_replace( pattern: " :.*", string: cipher_name, replace: "" );
		set_kb_item( name: "secpod_ssl_ciphers/" + ssl_ver + "/" + port + "/supported_ciphers", value: cipherName );
		set_kb_item( name: "secpod_ssl_ciphers/" + ssl_ver + "/" + port + "/medium_ciphers", value: cipherName );
		set_kb_item( name: "secpod_ssl_ciphers/" + ssl_ver + "/" + port + "/nonweak_ciphers", value: cipherName );
		set_kb_item( name: "secpod_ssl_ciphers/supported_ciphers", value: TRUE );
		set_kb_item( name: "secpod_ssl_ciphers/nonweak_ciphers", value: TRUE );
		set_kb_item( name: "secpod_ssl_ciphers/medium_ciphers", value: TRUE );
	}
	if(ContainsString( cipher_name, "Weak cipher" )){
		cipherName = ereg_replace( pattern: " :.*", string: cipher_name, replace: "" );
		set_kb_item( name: "secpod_ssl_ciphers/" + ssl_ver + "/" + port + "/supported_ciphers", value: cipherName );
		set_kb_item( name: "secpod_ssl_ciphers/" + ssl_ver + "/" + port + "/weak_ciphers", value: cipherName );
		set_kb_item( name: "secpod_ssl_ciphers/supported_ciphers", value: TRUE );
		set_kb_item( name: "secpod_ssl_ciphers/weak_ciphers", value: TRUE );
	}
	if(ContainsString( cipher_name, "Null cipher" )){
		cipherName = ereg_replace( pattern: " :.*", string: cipher_name, replace: "" );
		set_kb_item( name: "secpod_ssl_ciphers/" + ssl_ver + "/" + port + "/supported_ciphers", value: cipherName );
		set_kb_item( name: "secpod_ssl_ciphers/" + ssl_ver + "/" + port + "/null_ciphers", value: cipherName );
		set_kb_item( name: "secpod_ssl_ciphers/supported_ciphers", value: TRUE );
		set_kb_item( name: "secpod_ssl_ciphers/null_ciphers", value: TRUE );
	}
	if(ContainsString( cipher_name, "_anon_" )){
		cipherName = ereg_replace( pattern: " :.*", string: cipher_name, replace: "" );
		set_kb_item( name: "secpod_ssl_ciphers/" + ssl_ver + "/" + port + "/anon_ciphers", value: cipherName );
		set_kb_item( name: "secpod_ssl_ciphers/anon_ciphers", value: TRUE );
	}
}
func check_cipher_specs_supported( cipher_list, cipher_names, version, port ){
	var cipher_list, cipher_names, version, port;
	var v, x, all_done, max_req, seen_ciphers, hello_done, soc, hello, data, record, server_cipher;
	if(!cipher_list){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#cipher_list#-#check_cipher_specs_supported" );
		return;
	}
	if(!version){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#version#-#check_cipher_specs_supported" );
		return;
	}
	if(!cipher_names){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#cipher_names#-#check_cipher_specs_supported" );
		return;
	}
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#check_cipher_specs_supported" );
		return;
	}
	if( version == "tlsv1_3" ) {
		v = TLS_13;
	}
	else {
		if( version == "tlsv1_2" ) {
			v = TLS_12;
		}
		else {
			if( version == "tlsv1_1" ) {
				v = TLS_11;
			}
			else {
				if( version == "tlsv1" ) {
					v = TLS_10;
				}
				else {
					if(version == "sslv3"){
						v = SSL_v3;
					}
				}
			}
		}
	}
	if(!v){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#v#-#check_cipher_specs_supported" );
		return;
	}
	x = 0;
	all_done = FALSE;
	max_req = ( strlen( cipher_list ) / 2 );
	seen_ciphers = "";
	for(;TRUE && !all_done;){
		x++;
		hello_done = FALSE;
		if(strlen( cipher_list ) < 2){
			return;
		}
		if(!soc = open_ssl_socket( port: port )){
			return;
		}
		if(!hello = ssl_hello( ciphers: cipher_list, version: v, port: port )){
			close( soc );
			return;
		}
		send( socket: soc, data: hello );
		for(;!hello_done;){
			if(!data = ssl_recv( socket: soc )){
				close( soc );
				hello_done = TRUE;
				all_done = TRUE;
				return;
			}
			if(record = search_ssl_record( data: data, search: make_array( "handshake_typ", SSLv3_SERVER_HELLO ) )){
				if( record["cipher_spec"] ){
					server_cipher = mkword( record["cipher_spec"] );
					if( server_cipher ){
						if(seen_ciphers && ContainsString( seen_ciphers, server_cipher )){
							close( soc );
							hello_done = TRUE;
							all_done = TRUE;
							return;
						}
						seen_ciphers += server_cipher;
						report_cipher( cipher_name: cipher_names[hexstr( server_cipher )], port: port, ssl_ver: version );
						cipher_list = remove_cipher_from_list( list: cipher_list, cipher: server_cipher );
						hello_done = TRUE;
						close( soc );
						continue;
					}
					else {
						close( soc );
						hello_done = TRUE;
						all_done = TRUE;
						return;
					}
				}
				else {
					close( soc );
					hello_done = TRUE;
					all_done = TRUE;
					return;
				}
			}
			if(search_ssl_record( data: data, search: make_array( "content_typ", SSLv3_ALERT ) )){
				close( soc );
				hello_done = TRUE;
				all_done = TRUE;
				return;
			}
			if(search_ssl_record( data: data, search: make_array( "handshake_typ", SSLv3_SERVER_HELLO_DONE ) )){
				close( soc );
				hello_done = TRUE;
				continue;
			}
		}
		if(x > max_req){
			close( soc );
			hello_done = TRUE;
			all_done = TRUE;
			return;
		}
	}
	return;
}
func remove_cipher_from_list( list, cipher ){
	var list, cipher;
	return str_replace( string: list, find: cipher, replace: "" );
}
func check_single_cipher( tls_versions, port ){
	var tls_versions, port;
	var _tlsv, cipher_names, SSL_VER, _cipher, CIPHER_CODE, CIPHER_NAME;
	if(!tls_versions){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#tls_versions#-#check_single_cipher" );
		return;
	}
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#check_single_cipher" );
		return;
	}
	for _tlsv in tls_versions {
		cipher_names = make_array();
		SSL_VER = FALSE;
		if( _tlsv == "SSLv2" ) {
			continue;
		}
		else {
			if( _tlsv == "SSLv3" ) {
				SSL_VER = "sslv3";
			}
			else {
				if( _tlsv == "TLSv1.0" ) {
					SSL_VER = "tlsv1";
				}
				else {
					if( _tlsv == "TLSv1.1" ) {
						SSL_VER = "tlsv1_1";
					}
					else {
						if( _tlsv == "TLSv1.2" ) {
							SSL_VER = "tlsv1_2";
						}
						else {
							if(_tlsv == "TLSv1.3"){
								SSL_VER = "tlsv1_3";
							}
						}
					}
				}
			}
		}
		for _cipher in keys( sslv3_tls_ciphers ) {
			CIPHER_CODE = sslv3_tls_ciphers[_cipher];
			CIPHER_NAME = _cipher;
			CIPHER_NAME = cipher_has_strength_override( cn: CIPHER_NAME );
			cipher_names[hexstr( CIPHER_CODE )] = CIPHER_NAME;
			check_cipher_specs_supported( cipher_list: CIPHER_CODE, cipher_names: cipher_names, version: SSL_VER, port: port );
		}
	}
}
func check_all_cipher( tls_versions, port ){
	var tls_versions, port;
	var _tlsv, cipher_names, initial_cipher_list, CHACHA_CIPHERS, SSL_VER, _cipher, CIPHER_CODE, CIPHER_NAME;
	if(!tls_versions){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#tls_versions#-#check_all_cipher" );
		return;
	}
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#check_all_cipher" );
		return;
	}
	for _tlsv in tls_versions {
		cipher_names = make_array();
		initial_cipher_list = "";
		CHACHA_CIPHERS = "";
		SSL_VER = FALSE;
		if( _tlsv == "SSLv2" ) {
			continue;
		}
		else {
			if( _tlsv == "SSLv3" ) {
				SSL_VER = "sslv3";
			}
			else {
				if( _tlsv == "TLSv1.0" ) {
					SSL_VER = "tlsv1";
				}
				else {
					if( _tlsv == "TLSv1.1" ) {
						SSL_VER = "tlsv1_1";
					}
					else {
						if( _tlsv == "TLSv1.2" ) {
							SSL_VER = "tlsv1_2";
						}
						else {
							if(_tlsv == "TLSv1.3"){
								SSL_VER = "tlsv1_3";
							}
						}
					}
				}
			}
		}
		for _cipher in keys( sslv3_tls_ciphers ) {
			CIPHER_CODE = sslv3_tls_ciphers[_cipher];
			CIPHER_NAME = _cipher;
			CIPHER_NAME = cipher_has_strength_override( cn: CIPHER_NAME );
			cipher_names[hexstr( CIPHER_CODE )] = CIPHER_NAME;
			if( !ContainsString( CIPHER_NAME, "CHACHA20" ) ) {
				initial_cipher_list += CIPHER_CODE;
			}
			else {
				CHACHA_CIPHERS += CIPHER_CODE;
			}
		}
		if(strlen( initial_cipher_list )){
			if(strlen( CHACHA_CIPHERS )){
				initial_cipher_list = CHACHA_CIPHERS + initial_cipher_list;
			}
			check_cipher_specs_supported( cipher_list: initial_cipher_list, cipher_names: cipher_names, version: SSL_VER, port: port );
		}
	}
}

