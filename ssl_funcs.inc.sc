var _ssl_funcs_debug;
_ssl_funcs_debug = FALSE;
var SSLv3_SERVER_HELLO, SSLv3_SERVER_HELLO_DONE, SSLv3_CLIENT_HELLO, SSLv3_SERVER_KEY_EXCHANGE, SSLv3_CERTIFICATE, SSLv3_CERTIFICATE_REQUEST, SSLv3_CERTIFICATE_STATUS;
var SSLv3_CHANGECIPHERSPEC, SSLv3_ALERT, SSLv3_HANDSHAKE, SSLv3_APPLICATION_DATA;
var SSLv2_SERVER_HELLO;
var SSLv3_ALERT_FATAL, SSLv3_ALERT_UNEXPECTED_MESSAGE, SSLv3_ALERT_BAD_RECORD_MAC, SSLv3_ALERT_DECRYPTION_FAILED, SSLv3_ALERT_HANDSHAKE_FAILURE, SSLv3_ALERT_UNRECOGNIZED_NAME;
var SSLv3_ALERT_INAPPROPRIATE_FALLBACK, SSLv3_ALERT_RECORD_OVERFLOW, SSLv3_CLIENT_KEY_EXCHANGE;
var version_string, version_kb_string_mapping, SSL_v2, SSL_v3, TLS_10, TLS_11, TLS_12, TLS_13;
var elliptic_curves, ec_point_formats, sslv2_raw_ciphers, sslv3_tls_raw_ciphers, compression_methods;
var application_layer_protocol_negotiation, npn_alpn_name_mapping, npn_alpn_protocol_list;
var __use_extended_ec;
__use_extended_ec = make_array();
var alpn_prot;
SSL_v2 = raw_string( 0x00, 0x02 );
SSL_v3 = raw_string( 0x03, 0x00 );
TLS_10 = raw_string( 0x03, 0x01 );
TLS_11 = raw_string( 0x03, 0x02 );
TLS_12 = raw_string( 0x03, 0x03 );
TLS_13 = raw_string( 0x03, 0x04 );
elliptic_curves["sect163k1"] = raw_string( 0, 1 );
elliptic_curves["sect163r1"] = raw_string( 0, 2 );
elliptic_curves["sect163r2"] = raw_string( 0, 3 );
elliptic_curves["sect193r1"] = raw_string( 0, 4 );
elliptic_curves["sect193r2"] = raw_string( 0, 5 );
elliptic_curves["sect233k1"] = raw_string( 0, 6 );
elliptic_curves["sect233r1"] = raw_string( 0, 7 );
elliptic_curves["sect239k1"] = raw_string( 0, 8 );
elliptic_curves["sect283k1"] = raw_string( 0, 9 );
elliptic_curves["sect283r1"] = raw_string( 0, 10 );
elliptic_curves["sect409k1"] = raw_string( 0, 11 );
elliptic_curves["sect409r1"] = raw_string( 0, 12 );
elliptic_curves["sect571k1"] = raw_string( 0, 13 );
elliptic_curves["sect571r1"] = raw_string( 0, 14 );
elliptic_curves["secp160k1"] = raw_string( 0, 15 );
elliptic_curves["secp160r1"] = raw_string( 0, 16 );
elliptic_curves["secp160r2"] = raw_string( 0, 17 );
elliptic_curves["secp192k1"] = raw_string( 0, 18 );
elliptic_curves["secp192r1"] = raw_string( 0, 19 );
elliptic_curves["secp224k1"] = raw_string( 0, 20 );
elliptic_curves["secp224r1"] = raw_string( 0, 21 );
elliptic_curves["secp256k1"] = raw_string( 0, 22 );
elliptic_curves["secp256r1"] = raw_string( 0, 23 );
elliptic_curves["secp384r1"] = raw_string( 0, 24 );
elliptic_curves["secp521r1"] = raw_string( 0, 25 );
elliptic_curves["brainpoolP256r1"] = raw_string( 0, 26 );
elliptic_curves["brainpoolP384r1"] = raw_string( 0, 27 );
elliptic_curves["brainpoolP512r1"] = raw_string( 0, 28 );
elliptic_curves["x25519"] = raw_string( 0, 29 );
elliptic_curves["x448"] = raw_string( 0, 30 );
elliptic_curves["ffdhe2048"] = raw_string( 0x01, 0x00 );
elliptic_curves["ffdhe3072"] = raw_string( 0x01, 0x01 );
elliptic_curves["ffdhe4096"] = raw_string( 0x01, 0x02 );
elliptic_curves["ffdhe6144"] = raw_string( 0x01, 0x03 );
elliptic_curves["ffdhe8192"] = raw_string( 0x01, 0x04 );
ec_point_formats["uncompressed"] = raw_string( 0 );
ec_point_formats["ansiX962_compressed_prime"] = raw_string( 1 );
ec_point_formats["ansiX962_compressed_char2"] = raw_string( 2 );
compression_methods["NULL"] = raw_string( 0 );
compression_methods["DEFLATE"] = raw_string( 1 );
compression_methods["LZS"] = raw_string( 64 );
application_layer_protocol_negotiation["http/1.1"] = raw_string( 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31 );
application_layer_protocol_negotiation["spdy/1"] = raw_string( 0x73, 0x70, 0x64, 0x79, 0x2f, 0x31 );
application_layer_protocol_negotiation["spdy/2"] = raw_string( 0x73, 0x70, 0x64, 0x79, 0x2f, 0x32 );
application_layer_protocol_negotiation["spdy/3"] = raw_string( 0x73, 0x70, 0x64, 0x79, 0x2f, 0x33 );
application_layer_protocol_negotiation["spdy/3.1"] = raw_string( 0x73, 0x70, 0x64, 0x79, 0x2f, 0x33, 0x2e, 0x31 );
application_layer_protocol_negotiation["spdy/4"] = raw_string( 0x73, 0x70, 0x64, 0x79, 0x2f, 0x34 );
application_layer_protocol_negotiation["h2"] = raw_string( 0x68, 0x32 );
npn_alpn_name_mapping["http/1.0"] = "HTTP/1.0";
npn_alpn_name_mapping["http/1.1"] = "HTTP/1.1";
npn_alpn_name_mapping["spdy/1"] = "SPDY/1";
npn_alpn_name_mapping["spdy/2"] = "SPDY/2";
npn_alpn_name_mapping["spdy/3"] = "SPDY/3";
npn_alpn_name_mapping["spdy/3.1"] = "SPDY/3.1";
npn_alpn_name_mapping["spdy/4"] = "SPDY/4";
npn_alpn_name_mapping["h2"] = "HTTP/2";
application_layer_protocol_negotiation["grpc-exp"] = raw_string( 0x67, 0x72, 0x70, 0x63, 0x2d, 0x65, 0x78, 0x70 );
npn_alpn_name_mapping["grpc-exp"] = "gRPC";
npn_alpn_protocol_list = make_list( "http/1.1",
	 "spdy/1",
	 "spdy/2",
	 "spdy/3",
	 "spdy/3.1",
	 "spdy/4",
	 "h2",
	 "grpc-exp" );
version_kb_string_mapping[SSL_v2] = "sslv2";
version_kb_string_mapping[SSL_v3] = "sslv3";
version_kb_string_mapping[TLS_10] = "tlsv1";
version_kb_string_mapping[TLS_11] = "tlsv1_1";
version_kb_string_mapping[TLS_12] = "tlsv1_2";
version_kb_string_mapping[TLS_13] = "tlsv1_3";
version_string[SSL_v2] = "SSLv2";
version_string[SSL_v3] = "SSLv3";
version_string[TLS_10] = "TLSv1.0";
version_string[TLS_11] = "TLSv1.1";
version_string[TLS_12] = "TLSv1.2";
version_string[TLS_13] = "TLSv1.3";
SSLv3_CLIENT_HELLO = 1;
SSLv3_SERVER_HELLO = 2;
SSLv3_CERTIFICATE = 11;
SSLv3_SERVER_KEY_EXCHANGE = 12;
SSLv3_CERTIFICATE_REQUEST = 13;
SSLv3_SERVER_HELLO_DONE = 14;
SSLv3_CLIENT_KEY_EXCHANGE = 16;
SSLv3_CERTIFICATE_STATUS = 22;
SSLv3_CHANGECIPHERSPEC = 20;
SSLv3_ALERT = 21;
SSLv3_HANDSHAKE = 22;
SSLv3_APPLICATION_DATA = 23;
SSLv3_ALERT_FATAL = 2;
SSLv3_ALERT_UNEXPECTED_MESSAGE = 10;
SSLv3_ALERT_BAD_RECORD_MAC = 20;
SSLv3_ALERT_DECRYPTION_FAILED = 21;
SSLv3_ALERT_RECORD_OVERFLOW = 22;
SSLv3_ALERT_HANDSHAKE_FAILURE = 40;
SSLv3_ALERT_DECODE_ERROR = 50;
SSLv3_ALERT_INAPPROPRIATE_FALLBACK = 86;
SSLv3_ALERT_UNRECOGNIZED_NAME = 112;
SSLv2_SERVER_HELLO = 4;
sslv2_raw_ciphers["SSL2_NULL_WITH_MD5"] = raw_string( 0x00, 0x00, 0x00 );
sslv2_raw_ciphers["SSL2_RC4_128_MD5"] = raw_string( 0x01, 0x00, 0x80 );
sslv2_raw_ciphers["SSL2_RC4_128_EXPORT40_WITH_MD5"] = raw_string( 0x02, 0x00, 0x80 );
sslv2_raw_ciphers["SSL2_RC2_CBC_128_CBC_WITH_MD5"] = raw_string( 0x03, 0x00, 0x80 );
sslv2_raw_ciphers["SSL2_RC2_CBC_128_CBC_EXPORT40_WITH_MD5"] = raw_string( 0x04, 0x00, 0x80 );
sslv2_raw_ciphers["SSL2_IDEA_128_CBC_WITH_MD5"] = raw_string( 0x05, 0x00, 0x80 );
sslv2_raw_ciphers["SSL2_DES_64_CBC_WITH_MD5"] = raw_string( 0x06, 0x00, 0x40 );
sslv2_raw_ciphers["SSL2_DES_64_CBC_WITH_SHA"] = raw_string( 0x06, 0x01, 0x40 );
sslv2_raw_ciphers["SSL2_DES_192_EDE3_CBC_WITH_MD5"] = raw_string( 0x07, 0x00, 0xc0 );
sslv2_raw_ciphers["SSL2_DES_192_EDE3_CBC_WITH_SHA"] = raw_string( 0x07, 0x01, 0xc0 );
sslv2_raw_ciphers["SSL2_RC4_64_WITH_MD5"] = raw_string( 0x08, 0x00, 0x80 );
sslv2_raw_ciphers["SSL2_DES_64_CFB64_WITH_MD5_1"] = raw_string( 0xff, 0x08, 0x00 );
sslv2_raw_ciphers["SSL2_NULL"] = raw_string( 0xff, 0x08, 0x10 );
sslv2_raw_ciphers["SSL2_UNKNOWN"] = raw_string( 0x06, 0x00, 0x80 );
sslv3_tls_raw_ciphers["TLS_NULL_WITH_NULL_NULL"] = raw_string( 0x00, 0x00 );
sslv3_tls_raw_ciphers["TLS_RSA_WITH_NULL_MD5"] = raw_string( 0x00, 0x01 );
sslv3_tls_raw_ciphers["TLS_RSA_WITH_NULL_SHA"] = raw_string( 0x00, 0x02 );
sslv3_tls_raw_ciphers["TLS_RSA_EXPORT_WITH_RC4_40_MD5"] = raw_string( 0x00, 0x03 );
sslv3_tls_raw_ciphers["TLS_RSA_WITH_RC4_128_MD5"] = raw_string( 0x00, 0x04 );
sslv3_tls_raw_ciphers["TLS_RSA_WITH_RC4_128_SHA"] = raw_string( 0x00, 0x05 );
sslv3_tls_raw_ciphers["TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"] = raw_string( 0x00, 0x06 );
sslv3_tls_raw_ciphers["TLS_RSA_WITH_IDEA_CBC_SHA"] = raw_string( 0x00, 0x07 );
sslv3_tls_raw_ciphers["TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"] = raw_string( 0x00, 0x08 );
sslv3_tls_raw_ciphers["TLS_RSA_WITH_DES_CBC_SHA"] = raw_string( 0x00, 0x09 );
sslv3_tls_raw_ciphers["TLS_RSA_WITH_3DES_EDE_CBC_SHA"] = raw_string( 0x00, 0x0A );
sslv3_tls_raw_ciphers["TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA"] = raw_string( 0x00, 0x0B );
sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_DES_CBC_SHA"] = raw_string( 0x00, 0x0C );
sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA"] = raw_string( 0x00, 0x0D );
sslv3_tls_raw_ciphers["TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA"] = raw_string( 0x00, 0x0E );
sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_DES_CBC_SHA"] = raw_string( 0x00, 0x0F );
sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA"] = raw_string( 0x00, 0x10 );
sslv3_tls_raw_ciphers["TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"] = raw_string( 0x00, 0x11 );
sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_DES_CBC_SHA"] = raw_string( 0x00, 0x12 );
sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"] = raw_string( 0x00, 0x13 );
sslv3_tls_raw_ciphers["TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"] = raw_string( 0x00, 0x14 );
sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_DES_CBC_SHA"] = raw_string( 0x00, 0x15 );
sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"] = raw_string( 0x00, 0x16 );
sslv3_tls_raw_ciphers["TLS_DH_anon_EXPORT_WITH_RC4_40_MD5"] = raw_string( 0x00, 0x17 );
sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_RC4_128_MD5"] = raw_string( 0x00, 0x18 );
sslv3_tls_raw_ciphers["TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA"] = raw_string( 0x00, 0x19 );
sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_DES_CBC_SHA"] = raw_string( 0x00, 0x1A );
sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"] = raw_string( 0x00, 0x1B );
sslv3_tls_raw_ciphers["TLS_FORTEZZA_KEA_WITH_NULL_SHA"] = raw_string( 0x00, 0x1C );
sslv3_tls_raw_ciphers["TLS_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA"] = raw_string( 0x00, 0x1D );
sslv3_tls_raw_ciphers["TLS_FORTEZZA_KEA_WITH_RC4_128_SHA or TLS_KRB5_WITH_DES_CBC_SHA"] = raw_string( 0x00, 0x1E );
sslv3_tls_raw_ciphers["TLS_KRB5_WITH_3DES_EDE_CBC_SHA"] = raw_string( 0x00, 0x1F );
sslv3_tls_raw_ciphers["TLS_KRB5_WITH_RC4_128_SHA"] = raw_string( 0x00, 0x20 );
sslv3_tls_raw_ciphers["TLS_KRB5_WITH_IDEA_CBC_SHA"] = raw_string( 0x00, 0x21 );
sslv3_tls_raw_ciphers["TLS_KRB5_WITH_DES_CBC_MD5"] = raw_string( 0x00, 0x22 );
sslv3_tls_raw_ciphers["TLS_KRB5_WITH_3DES_EDE_CBC_MD5"] = raw_string( 0x00, 0x23 );
sslv3_tls_raw_ciphers["TLS_KRB5_WITH_RC4_128_MD5"] = raw_string( 0x00, 0x24 );
sslv3_tls_raw_ciphers["TLS_KRB5_WITH_IDEA_CBC_MD5"] = raw_string( 0x00, 0x25 );
sslv3_tls_raw_ciphers["TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA"] = raw_string( 0x00, 0x26 );
sslv3_tls_raw_ciphers["TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA"] = raw_string( 0x00, 0x27 );
sslv3_tls_raw_ciphers["TLS_KRB5_EXPORT_WITH_RC4_40_SHA"] = raw_string( 0x00, 0x28 );
sslv3_tls_raw_ciphers["TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5"] = raw_string( 0x00, 0x29 );
sslv3_tls_raw_ciphers["TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5"] = raw_string( 0x00, 0x2A );
sslv3_tls_raw_ciphers["TLS_KRB5_EXPORT_WITH_RC4_40_MD5"] = raw_string( 0x00, 0x2B );
sslv3_tls_raw_ciphers["TLS_PSK_WITH_NULL_SHA"] = raw_string( 0x00, 0x2C );
sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_NULL_SHA"] = raw_string( 0x00, 0x2D );
sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_NULL_SHA"] = raw_string( 0x00, 0x2E );
sslv3_tls_raw_ciphers["TLS_RSA_WITH_AES_128_CBC_SHA"] = raw_string( 0x00, 0x2F );
sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_AES_128_CBC_SHA"] = raw_string( 0x00, 0x30 );
sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_AES_128_CBC_SHA"] = raw_string( 0x00, 0x31 );
sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_AES_128_CBC_SHA"] = raw_string( 0x00, 0x32 );
sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_AES_128_CBC_SHA"] = raw_string( 0x00, 0x33 );
sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_AES_128_CBC_SHA"] = raw_string( 0x00, 0x34 );
sslv3_tls_raw_ciphers["TLS_RSA_WITH_AES_256_CBC_SHA"] = raw_string( 0x00, 0x35 );
sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_AES_256_CBC_SHA"] = raw_string( 0x00, 0x36 );
sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_AES_256_CBC_SHA"] = raw_string( 0x00, 0x37 );
sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_AES_256_CBC_SHA"] = raw_string( 0x00, 0x38 );
sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_AES_256_CBC_SHA"] = raw_string( 0x00, 0x39 );
sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_AES_256_CBC_SHA"] = raw_string( 0x00, 0x3A );
sslv3_tls_raw_ciphers["TLS_RSA_WITH_NULL_SHA256"] = raw_string( 0x00, 0x3B );
sslv3_tls_raw_ciphers["TLS_RSA_WITH_AES_128_CBC_SHA256"] = raw_string( 0x00, 0x3C );
sslv3_tls_raw_ciphers["TLS_RSA_WITH_AES_256_CBC_SHA256"] = raw_string( 0x00, 0x3D );
sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_AES_128_CBC_SHA256"] = raw_string( 0x00, 0x3E );
sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_AES_128_CBC_SHA256"] = raw_string( 0x00, 0x3F );
sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"] = raw_string( 0x00, 0x40 );
sslv3_tls_raw_ciphers["TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"] = raw_string( 0x00, 0x41 );
sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA"] = raw_string( 0x00, 0x42 );
sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA"] = raw_string( 0x00, 0x43 );
sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA"] = raw_string( 0x00, 0x44 );
sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"] = raw_string( 0x00, 0x45 );
sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA"] = raw_string( 0x00, 0x46 );
sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_NULL_SHA (Draft)"] = raw_string( 0x00, 0x47 );
sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_RC4_128_SHA (Draft)"] = raw_string( 0x00, 0x48 );
sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_DES_CBC_SHA (Draft)"] = raw_string( 0x00, 0x49 );
sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA (Draft)"] = raw_string( 0x00, 0x4A );
sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA (Draft) or TLS_ECDH_ECDSA_EXPORT_WITH_RC4_40_SHA (Draft)"] = raw_string( 0x00, 0x4B );
sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA (Draft) or TLS_ECDH_ECDSA_EXPORT_WITH_RC4_56_SHA (Draft)"] = raw_string( 0x00, 0x4C );
sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_NULL_SHA (Draft)"] = raw_string( 0x00, 0x4D );
sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_RC4_128_SHA (Draft)"] = raw_string( 0x00, 0x4E );
sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_DES_CBC_SHA (Draft)"] = raw_string( 0x00, 0x4F );
sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA (Draft) or TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA (Draft)"] = raw_string( 0x00, 0x50 );
sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_AES_128_CBC_SHA (Draft) or TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA (Draft)"] = raw_string( 0x00, 0x51 );
sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_AES_256_CBC_SHA (Draft) or TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA (Draft)"] = raw_string( 0x00, 0x52 );
sslv3_tls_raw_ciphers["TLS_ECDH_RSA_EXPORT_WITH_RC4_40_SHA (Draft) or TLS_SRP_SHA_WITH_AES_128_CBC_SHA (Draft)"] = raw_string( 0x00, 0x53 );
sslv3_tls_raw_ciphers["TLS_ECDH_RSA_EXPORT_WITH_RC4_56_SHA (Draft) or TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA (Draft)"] = raw_string( 0x00, 0x54 );
sslv3_tls_raw_ciphers["TLS_ECDH_anon_NULL_WITH_SHA (Draft) or TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA (Draft)"] = raw_string( 0x00, 0x55 );
sslv3_tls_raw_ciphers["TLS_ECDH_anon_WITH_RC4_128_SHA (Draft) or TLS_SRP_SHA_WITH_AES_256_CBC_SHA (Draft)"] = raw_string( 0x00, 0x56 );
sslv3_tls_raw_ciphers["TLS_ECDH_anon_WITH_DES_CBC_SHA (Draft) or TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA (Draft)"] = raw_string( 0x00, 0x57 );
sslv3_tls_raw_ciphers["TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA (Draft) or TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA (Draft)"] = raw_string( 0x00, 0x58 );
sslv3_tls_raw_ciphers["TLS_ECDH_anon_EXPORT_WITH_DES40_CBC_SHA (Draft1)"] = raw_string( 0x00, 0x59 );
sslv3_tls_raw_ciphers["TLS_ECDH_anon_EXPORT_WITH_RC4_40_SHA (Draft1)"] = raw_string( 0x00, 0x5A );
sslv3_tls_raw_ciphers["TLS_ECDH_anon_EXPORT_WITH_DES40_CBC_SHA (Draft2)"] = raw_string( 0x00, 0x5B );
sslv3_tls_raw_ciphers["TLS_ECDH_anon_EXPORT_WITH_RC4_40_SHA (Draft2)"] = raw_string( 0x00, 0x5C );
sslv3_tls_raw_ciphers["TLS_RSA_EXPORT1024_WITH_RC4_56_MD5"] = raw_string( 0x00, 0x60 );
sslv3_tls_raw_ciphers["TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5"] = raw_string( 0x00, 0x61 );
sslv3_tls_raw_ciphers["TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA"] = raw_string( 0x00, 0x62 );
sslv3_tls_raw_ciphers["TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA"] = raw_string( 0x00, 0x63 );
sslv3_tls_raw_ciphers["TLS_RSA_EXPORT1024_WITH_RC4_56_SHA"] = raw_string( 0x00, 0x64 );
sslv3_tls_raw_ciphers["TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA"] = raw_string( 0x00, 0x65 );
sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_RC4_128_SHA"] = raw_string( 0x00, 0x66 );
sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"] = raw_string( 0x00, 0x67 );
sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_AES_256_CBC_SHA256"] = raw_string( 0x00, 0x68 );
sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_AES_256_CBC_SHA256"] = raw_string( 0x00, 0x69 );
sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"] = raw_string( 0x00, 0x6A );
sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"] = raw_string( 0x00, 0x6B );
sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_AES_128_CBC_SHA256"] = raw_string( 0x00, 0x6C );
sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_AES_256_CBC_SHA256"] = raw_string( 0x00, 0x6D );
sslv3_tls_raw_ciphers["TLS_KRB5_WITH_3DES_EDE_CBC_SHA (Draft)"] = raw_string( 0x00, 0x70 );
sslv3_tls_raw_ciphers["TLS_KRB5_WITH_3DES_EDE_CBC_MD5 (Draft)"] = raw_string( 0x00, 0x71 );
sslv3_tls_raw_ciphers["TLS_KRB5_WITH_RC4_128_SHA (Draft)"] = raw_string( 0x00, 0x72 );
sslv3_tls_raw_ciphers["TLS_KRB5_WITH_RC4_128_MD5 (Draft)"] = raw_string( 0x00, 0x73 );
sslv3_tls_raw_ciphers["TLS_KRB5_WITH_DES_CBC_SHA (Draft)"] = raw_string( 0x00, 0x74 );
sslv3_tls_raw_ciphers["TLS_KRB5_WITH_DES_CBC_MD5 (Draft)"] = raw_string( 0x00, 0x75 );
sslv3_tls_raw_ciphers["TLS_KRB5_WITH_AES_128_CBC_SHA (Draft)"] = raw_string( 0x00, 0x76 );
sslv3_tls_raw_ciphers["TLS_KRB5_WITH_AES_256_CBC_SHA (Draft)"] = raw_string( 0x00, 0x77 );
sslv3_tls_raw_ciphers["TLS_KRB5_WITH_NULL_SHA (Draft)"] = raw_string( 0x00, 0x78 );
sslv3_tls_raw_ciphers["TLS_KRB5_WITH_NULL_MD5 (Draft)"] = raw_string( 0x00, 0x79 );
sslv3_tls_raw_ciphers["TLS_GOSTR341094_WITH_28147_CNT_IMIT (Draft)"] = raw_string( 0x00, 0x80 );
sslv3_tls_raw_ciphers["TLS_GOSTR341001_WITH_28147_CNT_IMIT (Draft)"] = raw_string( 0x00, 0x81 );
sslv3_tls_raw_ciphers["TLS_GOSTR341094_WITH_NULL_GOSTR3411 (Draft)"] = raw_string( 0x00, 0x82 );
sslv3_tls_raw_ciphers["TLS_GOSTR341001_WITH_NULL_GOSTR3411 (Draft)"] = raw_string( 0x00, 0x83 );
sslv3_tls_raw_ciphers["TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"] = raw_string( 0x00, 0x84 );
sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA"] = raw_string( 0x00, 0x85 );
sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA"] = raw_string( 0x00, 0x86 );
sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA"] = raw_string( 0x00, 0x87 );
sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"] = raw_string( 0x00, 0x88 );
sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA"] = raw_string( 0x00, 0x89 );
sslv3_tls_raw_ciphers["TLS_PSK_WITH_RC4_128_SHA"] = raw_string( 0x00, 0x8A );
sslv3_tls_raw_ciphers["TLS_PSK_WITH_3DES_EDE_CBC_SHA"] = raw_string( 0x00, 0x8B );
sslv3_tls_raw_ciphers["TLS_PSK_WITH_AES_128_CBC_SHA"] = raw_string( 0x00, 0x8C );
sslv3_tls_raw_ciphers["TLS_PSK_WITH_AES_256_CBC_SHA"] = raw_string( 0x00, 0x8D );
sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_RC4_128_SHA"] = raw_string( 0x00, 0x8E );
sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA"] = raw_string( 0x00, 0x8F );
sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_AES_128_CBC_SHA"] = raw_string( 0x00, 0x90 );
sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_AES_256_CBC_SHA"] = raw_string( 0x00, 0x91 );
sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_RC4_128_SHA"] = raw_string( 0x00, 0x92 );
sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA"] = raw_string( 0x00, 0x93 );
sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_AES_128_CBC_SHA"] = raw_string( 0x00, 0x94 );
sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_AES_256_CBC_SHA"] = raw_string( 0x00, 0x95 );
sslv3_tls_raw_ciphers["TLS_RSA_WITH_SEED_CBC_SHA"] = raw_string( 0x00, 0x96 );
sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_SEED_CBC_SHA"] = raw_string( 0x00, 0x97 );
sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_SEED_CBC_SHA"] = raw_string( 0x00, 0x98 );
sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_SEED_CBC_SHA"] = raw_string( 0x00, 0x99 );
sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_SEED_CBC_SHA"] = raw_string( 0x00, 0x9A );
sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_SEED_CBC_SHA"] = raw_string( 0x00, 0x9B );
sslv3_tls_raw_ciphers["TLS_RSA_WITH_AES_128_GCM_SHA256"] = raw_string( 0x00, 0x9C );
sslv3_tls_raw_ciphers["TLS_RSA_WITH_AES_256_GCM_SHA384"] = raw_string( 0x00, 0x9D );
sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"] = raw_string( 0x00, 0x9E );
sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"] = raw_string( 0x00, 0x9F );
sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_AES_128_GCM_SHA256"] = raw_string( 0x00, 0xA0 );
sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_AES_256_GCM_SHA384"] = raw_string( 0x00, 0xA1 );
sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"] = raw_string( 0x00, 0xA2 );
sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"] = raw_string( 0x00, 0xA3 );
sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_AES_128_GCM_SHA256"] = raw_string( 0x00, 0xA4 );
sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_AES_256_GCM_SHA384"] = raw_string( 0x00, 0xA5 );
sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_AES_128_GCM_SHA256"] = raw_string( 0x00, 0xA6 );
sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_AES_256_GCM_SHA384"] = raw_string( 0x00, 0xA7 );
sslv3_tls_raw_ciphers["TLS_PSK_WITH_AES_128_GCM_SHA256"] = raw_string( 0x00, 0xA8 );
sslv3_tls_raw_ciphers["TLS_PSK_WITH_AES_256_GCM_SHA384"] = raw_string( 0x00, 0xA9 );
sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_AES_128_GCM_SHA256"] = raw_string( 0x00, 0xAA );
sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_AES_256_GCM_SHA384"] = raw_string( 0x00, 0xAB );
sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_AES_128_GCM_SHA256"] = raw_string( 0x00, 0xAC );
sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_AES_256_GCM_SHA384"] = raw_string( 0x00, 0xAD );
sslv3_tls_raw_ciphers["TLS_PSK_WITH_AES_128_CBC_SHA256"] = raw_string( 0x00, 0xAE );
sslv3_tls_raw_ciphers["TLS_PSK_WITH_AES_256_CBC_SHA384"] = raw_string( 0x00, 0xAF );
sslv3_tls_raw_ciphers["TLS_PSK_WITH_NULL_SHA256"] = raw_string( 0x00, 0xB0 );
sslv3_tls_raw_ciphers["TLS_PSK_WITH_NULL_SHA384"] = raw_string( 0x00, 0xB1 );
sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_AES_128_CBC_SHA256"] = raw_string( 0x00, 0xB2 );
sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_AES_256_CBC_SHA384"] = raw_string( 0x00, 0xB3 );
sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_NULL_SHA256"] = raw_string( 0x00, 0xB4 );
sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_NULL_SHA384"] = raw_string( 0x00, 0xB5 );
sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_AES_128_CBC_SHA256"] = raw_string( 0x00, 0xB6 );
sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_AES_256_CBC_SHA384"] = raw_string( 0x00, 0xB7 );
sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_NULL_SHA256"] = raw_string( 0x00, 0xB8 );
sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_NULL_SHA384"] = raw_string( 0x00, 0xB9 );
sslv3_tls_raw_ciphers["TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256"] = raw_string( 0x00, 0xBA );
sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256"] = raw_string( 0x00, 0xBB );
sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256"] = raw_string( 0x00, 0xBC );
sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256"] = raw_string( 0x00, 0xBD );
sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"] = raw_string( 0x00, 0xBE );
sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256"] = raw_string( 0x00, 0xBF );
sslv3_tls_raw_ciphers["TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256"] = raw_string( 0x00, 0xC0 );
sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256"] = raw_string( 0x00, 0xC1 );
sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256"] = raw_string( 0x00, 0xC2 );
sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256"] = raw_string( 0x00, 0xC3 );
sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256"] = raw_string( 0x00, 0xC4 );
sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256"] = raw_string( 0x00, 0xC5 );
sslv3_tls_raw_ciphers["TLS_AES_128_GCM_SHA256"] = raw_string( 0x13, 0x01 );
sslv3_tls_raw_ciphers["TLS_AES_256_GCM_SHA384"] = raw_string( 0x13, 0x02 );
sslv3_tls_raw_ciphers["TLS_CHACHA20_POLY1305_SHA256"] = raw_string( 0x13, 0x03 );
sslv3_tls_raw_ciphers["TLS_AES_128_CCM_SHA256"] = raw_string( 0x13, 0x04 );
sslv3_tls_raw_ciphers["TLS_AES_128_CCM_8_SHA256"] = raw_string( 0x13, 0x05 );
sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_NULL_SHA"] = raw_string( 0xC0, 0x01 );
sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_RC4_128_SHA"] = raw_string( 0xC0, 0x02 );
sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"] = raw_string( 0xC0, 0x03 );
sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"] = raw_string( 0xC0, 0x04 );
sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"] = raw_string( 0xC0, 0x05 );
sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_NULL_SHA"] = raw_string( 0xC0, 0x06 );
sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"] = raw_string( 0xC0, 0x07 );
sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"] = raw_string( 0xC0, 0x08 );
sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"] = raw_string( 0xC0, 0x09 );
sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"] = raw_string( 0xC0, 0x0A );
sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_NULL_SHA"] = raw_string( 0xC0, 0x0B );
sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_RC4_128_SHA"] = raw_string( 0xC0, 0x0C );
sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA"] = raw_string( 0xC0, 0x0D );
sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"] = raw_string( 0xC0, 0x0E );
sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"] = raw_string( 0xC0, 0x0F );
sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_NULL_SHA"] = raw_string( 0xC0, 0x10 );
sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_RC4_128_SHA"] = raw_string( 0xC0, 0x11 );
sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"] = raw_string( 0xC0, 0x12 );
sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"] = raw_string( 0xC0, 0x13 );
sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"] = raw_string( 0xC0, 0x14 );
sslv3_tls_raw_ciphers["TLS_ECDH_anon_WITH_NULL_SHA"] = raw_string( 0xC0, 0x15 );
sslv3_tls_raw_ciphers["TLS_ECDH_anon_WITH_RC4_128_SHA"] = raw_string( 0xC0, 0x16 );
sslv3_tls_raw_ciphers["TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA"] = raw_string( 0xC0, 0x17 );
sslv3_tls_raw_ciphers["TLS_ECDH_anon_WITH_AES_128_CBC_SHA"] = raw_string( 0xC0, 0x18 );
sslv3_tls_raw_ciphers["TLS_ECDH_anon_WITH_AES_256_CBC_SHA"] = raw_string( 0xC0, 0x19 );
sslv3_tls_raw_ciphers["TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA"] = raw_string( 0xC0, 0x1A );
sslv3_tls_raw_ciphers["TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA"] = raw_string( 0xC0, 0x1B );
sslv3_tls_raw_ciphers["TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA"] = raw_string( 0xC0, 0x1C );
sslv3_tls_raw_ciphers["TLS_SRP_SHA_WITH_AES_128_CBC_SHA"] = raw_string( 0xC0, 0x1D );
sslv3_tls_raw_ciphers["TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA"] = raw_string( 0xC0, 0x1E );
sslv3_tls_raw_ciphers["TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA"] = raw_string( 0xC0, 0x1F );
sslv3_tls_raw_ciphers["TLS_SRP_SHA_WITH_AES_256_CBC_SHA"] = raw_string( 0xC0, 0x20 );
sslv3_tls_raw_ciphers["TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA"] = raw_string( 0xC0, 0x21 );
sslv3_tls_raw_ciphers["TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA"] = raw_string( 0xC0, 0x22 );
sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"] = raw_string( 0xC0, 0x23 );
sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"] = raw_string( 0xC0, 0x24 );
sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"] = raw_string( 0xC0, 0x25 );
sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"] = raw_string( 0xC0, 0x26 );
sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"] = raw_string( 0xC0, 0x27 );
sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"] = raw_string( 0xC0, 0x28 );
sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256"] = raw_string( 0xC0, 0x29 );
sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"] = raw_string( 0xC0, 0x2A );
sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"] = raw_string( 0xC0, 0x2B );
sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"] = raw_string( 0xC0, 0x2C );
sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"] = raw_string( 0xC0, 0x2D );
sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"] = raw_string( 0xC0, 0x2E );
sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"] = raw_string( 0xC0, 0x2F );
sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"] = raw_string( 0xC0, 0x30 );
sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256"] = raw_string( 0xC0, 0x31 );
sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"] = raw_string( 0xC0, 0x32 );
sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_RC4_128_SHA"] = raw_string( 0xC0, 0x33 );
sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA"] = raw_string( 0xC0, 0x34 );
sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA"] = raw_string( 0xC0, 0x35 );
sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA"] = raw_string( 0xC0, 0x36 );
sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256"] = raw_string( 0xC0, 0x37 );
sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384"] = raw_string( 0xC0, 0x38 );
sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_NULL_SHA"] = raw_string( 0xC0, 0x39 );
sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_NULL_SHA256"] = raw_string( 0xC0, 0x3A );
sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_NULL_SHA384"] = raw_string( 0xC0, 0x3B );
sslv3_tls_raw_ciphers["TLS_RSA_WITH_ARIA_128_CBC_SHA256"] = raw_string( 0xC0, 0x3C );
sslv3_tls_raw_ciphers["TLS_RSA_WITH_ARIA_256_CBC_SHA384"] = raw_string( 0xC0, 0x3D );
sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256"] = raw_string( 0xC0, 0x3E );
sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384"] = raw_string( 0xC0, 0x3F );
sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256"] = raw_string( 0xC0, 0x40 );
sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384"] = raw_string( 0xC0, 0x41 );
sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256"] = raw_string( 0xC0, 0x42 );
sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384"] = raw_string( 0xC0, 0x43 );
sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256"] = raw_string( 0xC0, 0x44 );
sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384"] = raw_string( 0xC0, 0x45 );
sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_ARIA_128_CBC_SHA256"] = raw_string( 0xC0, 0x46 );
sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_ARIA_256_CBC_SHA384"] = raw_string( 0xC0, 0x47 );
sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256"] = raw_string( 0xC0, 0x48 );
sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384"] = raw_string( 0xC0, 0x49 );
sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256"] = raw_string( 0xC0, 0x4A );
sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384"] = raw_string( 0xC0, 0x4B );
sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256"] = raw_string( 0xC0, 0x4C );
sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384"] = raw_string( 0xC0, 0x4D );
sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256"] = raw_string( 0xC0, 0x4E );
sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384"] = raw_string( 0xC0, 0x4F );
sslv3_tls_raw_ciphers["TLS_RSA_WITH_ARIA_128_GCM_SHA256"] = raw_string( 0xC0, 0x50 );
sslv3_tls_raw_ciphers["TLS_RSA_WITH_ARIA_256_GCM_SHA384"] = raw_string( 0xC0, 0x51 );
sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256"] = raw_string( 0xC0, 0x52 );
sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384"] = raw_string( 0xC0, 0x53 );
sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256"] = raw_string( 0xC0, 0x54 );
sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384"] = raw_string( 0xC0, 0x55 );
sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256"] = raw_string( 0xC0, 0x56 );
sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384"] = raw_string( 0xC0, 0x57 );
sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256"] = raw_string( 0xC0, 0x58 );
sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384"] = raw_string( 0xC0, 0x59 );
sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_ARIA_128_GCM_SHA256"] = raw_string( 0xC0, 0x5A );
sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_ARIA_256_GCM_SHA384"] = raw_string( 0xC0, 0x5B );
sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256"] = raw_string( 0xC0, 0x5C );
sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384"] = raw_string( 0xC0, 0x5D );
sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256"] = raw_string( 0xC0, 0x5E );
sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384"] = raw_string( 0xC0, 0x5F );
sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256"] = raw_string( 0xC0, 0x60 );
sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384"] = raw_string( 0xC0, 0x61 );
sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256"] = raw_string( 0xC0, 0x62 );
sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384"] = raw_string( 0xC0, 0x63 );
sslv3_tls_raw_ciphers["TLS_PSK_WITH_ARIA_128_CBC_SHA256"] = raw_string( 0xC0, 0x64 );
sslv3_tls_raw_ciphers["TLS_PSK_WITH_ARIA_256_CBC_SHA384"] = raw_string( 0xC0, 0x65 );
sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256"] = raw_string( 0xC0, 0x66 );
sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384"] = raw_string( 0xC0, 0x67 );
sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256"] = raw_string( 0xC0, 0x68 );
sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384"] = raw_string( 0xC0, 0x69 );
sslv3_tls_raw_ciphers["TLS_PSK_WITH_ARIA_128_GCM_SHA256"] = raw_string( 0xC0, 0x6A );
sslv3_tls_raw_ciphers["TLS_PSK_WITH_ARIA_256_GCM_SHA384"] = raw_string( 0xC0, 0x6B );
sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256"] = raw_string( 0xC0, 0x6C );
sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384"] = raw_string( 0xC0, 0x6D );
sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256"] = raw_string( 0xC0, 0x6E );
sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384"] = raw_string( 0xC0, 0x6F );
sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256"] = raw_string( 0xC0, 0x70 );
sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384"] = raw_string( 0xC0, 0x71 );
sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"] = raw_string( 0xC0, 0x72 );
sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"] = raw_string( 0xC0, 0x73 );
sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"] = raw_string( 0xC0, 0x74 );
sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"] = raw_string( 0xC0, 0x75 );
sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"] = raw_string( 0xC0, 0x76 );
sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384"] = raw_string( 0xC0, 0x77 );
sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256"] = raw_string( 0xC0, 0x78 );
sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384"] = raw_string( 0xC0, 0x79 );
sslv3_tls_raw_ciphers["TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256"] = raw_string( 0xC0, 0x7A );
sslv3_tls_raw_ciphers["TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384"] = raw_string( 0xC0, 0x7B );
sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256"] = raw_string( 0xC0, 0x7C );
sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384"] = raw_string( 0xC0, 0x7D );
sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256"] = raw_string( 0xC0, 0x7E );
sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384"] = raw_string( 0xC0, 0x7F );
sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256"] = raw_string( 0xC0, 0x80 );
sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384"] = raw_string( 0xC0, 0x81 );
sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256"] = raw_string( 0xC0, 0x82 );
sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384"] = raw_string( 0xC0, 0x83 );
sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256"] = raw_string( 0xC0, 0x84 );
sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384"] = raw_string( 0xC0, 0x85 );
sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"] = raw_string( 0xC0, 0x86 );
sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384"] = raw_string( 0xC0, 0x87 );
sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"] = raw_string( 0xC0, 0x88 );
sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384"] = raw_string( 0xC0, 0x89 );
sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256"] = raw_string( 0xC0, 0x8A );
sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384"] = raw_string( 0xC0, 0x8B );
sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256"] = raw_string( 0xC0, 0x8C );
sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384"] = raw_string( 0xC0, 0x8D );
sslv3_tls_raw_ciphers["TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256"] = raw_string( 0xC0, 0x8E );
sslv3_tls_raw_ciphers["TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384"] = raw_string( 0xC0, 0x8F );
sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256"] = raw_string( 0xC0, 0x90 );
sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384"] = raw_string( 0xC0, 0x91 );
sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256"] = raw_string( 0xC0, 0x92 );
sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384"] = raw_string( 0xC0, 0x93 );
sslv3_tls_raw_ciphers["TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256"] = raw_string( 0xC0, 0x94 );
sslv3_tls_raw_ciphers["TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384"] = raw_string( 0xC0, 0x95 );
sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"] = raw_string( 0xC0, 0x96 );
sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"] = raw_string( 0xC0, 0x97 );
sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256"] = raw_string( 0xC0, 0x98 );
sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384"] = raw_string( 0xC0, 0x99 );
sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"] = raw_string( 0xC0, 0x9A );
sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"] = raw_string( 0xC0, 0x9B );
sslv3_tls_raw_ciphers["TLS_RSA_WITH_AES_128_CCM"] = raw_string( 0xC0, 0x9C );
sslv3_tls_raw_ciphers["TLS_RSA_WITH_AES_256_CCM"] = raw_string( 0xC0, 0x9D );
sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_AES_128_CCM"] = raw_string( 0xC0, 0x9E );
sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_AES_256_CCM"] = raw_string( 0xC0, 0x9F );
sslv3_tls_raw_ciphers["TLS_RSA_WITH_AES_128_CCM_8"] = raw_string( 0xC0, 0xA0 );
sslv3_tls_raw_ciphers["TLS_RSA_WITH_AES_256_CCM_8"] = raw_string( 0xC0, 0xA1 );
sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_AES_128_CCM_8"] = raw_string( 0xC0, 0xA2 );
sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_AES_256_CCM_8"] = raw_string( 0xC0, 0xA3 );
sslv3_tls_raw_ciphers["TLS_PSK_WITH_AES_128_CCM"] = raw_string( 0xC0, 0xA4 );
sslv3_tls_raw_ciphers["TLS_PSK_WITH_AES_256_CCM"] = raw_string( 0xC0, 0xA5 );
sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_AES_128_CCM"] = raw_string( 0xC0, 0xA6 );
sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_AES_256_CCM"] = raw_string( 0xC0, 0xA7 );
sslv3_tls_raw_ciphers["TLS_PSK_WITH_AES_128_CCM_8"] = raw_string( 0xC0, 0xA8 );
sslv3_tls_raw_ciphers["TLS_PSK_WITH_AES_256_CCM_8"] = raw_string( 0xC0, 0xA9 );
sslv3_tls_raw_ciphers["TLS_PSK_DHE_WITH_AES_128_CCM_8"] = raw_string( 0xC0, 0xAA );
sslv3_tls_raw_ciphers["TLS_PSK_DHE_WITH_AES_256_CCM_8"] = raw_string( 0xC0, 0xAB );
sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_AES_128_CCM"] = raw_string( 0xC0, 0xAC );
sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_AES_256_CCM"] = raw_string( 0xC0, 0xAD );
sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8"] = raw_string( 0xC0, 0xAE );
sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8"] = raw_string( 0xC0, 0xAF );
sslv3_tls_raw_ciphers["TLS_ECCPWD_WITH_AES_128_GCM_SHA256 (Draft)"] = raw_string( 0xC0, 0xB0 );
sslv3_tls_raw_ciphers["TLS_ECCPWD_WITH_AES_256_GCM_SHA384 (Draft)"] = raw_string( 0xC0, 0xB1 );
sslv3_tls_raw_ciphers["TLS_ECCPWD_WITH_AES_128_CCM_SHA256 (Draft)"] = raw_string( 0xC0, 0xB2 );
sslv3_tls_raw_ciphers["TLS_ECCPWD_WITH_AES_256_CCM_SHA384 (Draft)"] = raw_string( 0xC0, 0xB3 );
sslv3_tls_raw_ciphers["TLS_SHA256_SHA256 (Draft)"] = raw_string( 0xC0, 0xB4 );
sslv3_tls_raw_ciphers["TLS_SHA384_SHA384 (Draft)"] = raw_string( 0xC0, 0xB5 );
sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (Draft)"] = raw_string( 0xCC, 0x13 );
sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (Draft)"] = raw_string( 0xCC, 0x14 );
sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (Draft)"] = raw_string( 0xCC, 0x15 );
sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"] = raw_string( 0xCC, 0xA8 );
sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"] = raw_string( 0xCC, 0xA9 );
sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"] = raw_string( 0xCC, 0xAA );
sslv3_tls_raw_ciphers["TLS_PSK_WITH_CHACHA20_POLY1305_SHA256"] = raw_string( 0xCC, 0xAB );
sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256"] = raw_string( 0xCC, 0xAC );
sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256"] = raw_string( 0xCC, 0xAD );
sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256"] = raw_string( 0xCC, 0xAE );
sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256"] = raw_string( 0xD0, 0x01 );
sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384"] = raw_string( 0xD0, 0x01 );
sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256"] = raw_string( 0xD0, 0x01 );
sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256"] = raw_string( 0xD0, 0x01 );
sslv3_tls_raw_ciphers["TLS_RSA_WITH_ESTREAM_SALSA20_SHA1 (Draft)"] = raw_string( 0xE4, 0x10 );
sslv3_tls_raw_ciphers["TLS_RSA_WITH_SALSA20_SHA1 (Draft)"] = raw_string( 0xE4, 0x11 );
sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_ESTREAM_SALSA20_SHA1 (Draft)"] = raw_string( 0xE4, 0x12 );
sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_SALSA20_SHA1 (Draft)"] = raw_string( 0xE4, 0x13 );
sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_ESTREAM_SALSA20_SHA1 (Draft)"] = raw_string( 0xE4, 0x14 );
sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_SALSA20_SHA1 (Draft)"] = raw_string( 0xE4, 0x15 );
sslv3_tls_raw_ciphers["TLS_PSK_WITH_ESTREAM_SALSA20_SHA1 (Draft)"] = raw_string( 0xE4, 0x16 );
sslv3_tls_raw_ciphers["TLS_PSK_WITH_SALSA20_SHA1 (Draft)"] = raw_string( 0xE4, 0x17 );
sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_ESTREAM_SALSA20_SHA1 (Draft)"] = raw_string( 0xE4, 0x18 );
sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_SALSA20_SHA1 (Draft)"] = raw_string( 0xE4, 0x19 );
sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_ESTREAM_SALSA20_SHA1 (Draft)"] = raw_string( 0xE4, 0x1A );
sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_SALSA20_SHA1 (Draft)"] = raw_string( 0xE4, 0x1B );
sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_ESTREAM_SALSA20_SHA1 (Draft)"] = raw_string( 0xE4, 0x1C );
sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_SALSA20_SHA1 (Draft)"] = raw_string( 0xE4, 0x1D );
sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_ESTREAM_SALSA20_SHA1 (Draft)"] = raw_string( 0xE4, 0x1E );
sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_SALSA20_SHA1 (Draft)"] = raw_string( 0xE4, 0x1F );
sslv3_tls_raw_ciphers["TLS_RSA_FIPS_WITH_DES_CBC_SHA (Draft)"] = raw_string( 0xFE, 0xFE );
sslv3_tls_raw_ciphers["TLS_RSA_FIPS_WITH_3DES_EDE_CBC_SHA (Draft)"] = raw_string( 0xFE, 0xFF );
sslv3_tls_raw_ciphers["TLS_RSA_FIPS_WITH_3DES_EDE_CBC_SHA_2 (Draft)"] = raw_string( 0xFF, 0xE0 );
sslv3_tls_raw_ciphers["TLS_RSA_FIPS_WITH_DES_CBC_SHA_2 (Draft)"] = raw_string( 0xFF, 0xE1 );
sslv3_tls_raw_ciphers["TLS_RSA_WITH_RC2_CBC_MD5 (Draft)"] = raw_string( 0xFF, 0x80 );
sslv3_tls_raw_ciphers["TLS_RSA_WITH_IDEA_CBC_MD5 (Draft)"] = raw_string( 0xFF, 0x81 );
sslv3_tls_raw_ciphers["TLS_RSA_WITH_DES_CBC_MD5 (Draft)"] = raw_string( 0xFF, 0x82 );
sslv3_tls_raw_ciphers["TLS_RSA_WITH_3DES_EDE_CBC_MD5 (Draft)"] = raw_string( 0xFF, 0x83 );
func get_cert_from_port( port, extensions ){
	var port, extensions;
	var soc, version, hello, hello_done, data, ret, cl;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#get_cert_from_port" );
		return;
	}
	if(!soc = open_ssl_socket( port: port )){
		return;
	}
	if(!version = get_supported_tls_version( port: port, min: TLS_10 )){
		version = TLS_10;
	}
	if(get_kb_item( "sni/" + port + "/supported" )){
		extensions = make_list( "sni" );
	}
	if(!hello = ssl_hello( port: port, version: version, extensions: extensions )){
		close( soc );
		return;
	}
	send( socket: soc, data: hello );
	for(;!hello_done;){
		if(!data = ssl_recv( socket: soc )){
			close( soc );
			return;
		}
		ret = search_ssl_record( data: data, search: make_array( "handshake_typ", SSLv3_CERTIFICATE ) );
		if(ret){
			cl = ret["cert_list"];
			if(cl[0]){
				set_kb_item( name: "ssl/" + port + "/server_cert", value: base64( str: cl[0] ) );
				close( soc );
				return cl[0];
			}
		}
		ret = search_ssl_record( data: data, search: make_array( "handshake_typ", SSLv3_SERVER_HELLO_DONE, "content_typ", SSLv3_ALERT ) );
		if(ret){
			hello_done = TRUE;
			break;
		}
	}
	close( soc );
	return;
}
func get_server_cert( port ){
	var port;
	var cert, soc;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#get_server_cert" );
		return;
	}
	if(!get_port_state( port )){
		return;
	}
	if(cert = get_kb_item( "ssl/" + port + "/server_cert" )){
		return base64_decode( str: cert );
	}
	if(get_kb_item( "sni/" + port + "/supported" )){
		return get_cert_from_port( port: port );
	}
	if( !get_kb_item( "starttls_typ/" + port ) ){
		if(get_port_transport( port ) < ENCAPS_SSLv23){
			if(tls_ssl_is_enabled( port: port )){
				return get_cert_from_port( port: port );
			}
			return;
		}
		soc = open_sock_tcp( port );
		if(soc){
			cert = socket_get_cert( socket: soc );
			close( soc );
			if(cert){
				set_kb_item( name: "ssl/" + port + "/server_cert", value: base64( str: cert ) );
				return cert;
			}
			return;
		}
		return;
	}
	else {
		return get_cert_from_port( port: port );
	}
}
func cert_summary( key ){
	var key;
	var sanList, _tmpSan, san, cert_info;
	if(!key){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#key#-#cert_summary" );
		return NULL;
	}
	sanList = get_kb_list( key + "subject/*" );
	for _tmpSan in sanList {
		if(ContainsString( _tmpSan, "dns-name" )){
			_tmpSan = eregmatch( pattern: "\\(dns-name (.*)\\)", string: _tmpSan );
			if(!isnull( _tmpSan )){
				san += _tmpSan[1] + ", ";
			}
		}
	}
	if( !isnull( san ) ) {
		san = ereg_replace( string: san, pattern: "(, )$", replace: "" );
	}
	else {
		san = "None";
	}
	cert_info = make_array();
	cert_info["subject"] = get_kb_item( key + "subject" );
	cert_info["subject alternative names (SAN)"] = san;
	cert_info["issued by"] = get_kb_item( key + "issuer" );
	cert_info["serial"] = get_kb_item( key + "serial" );
	cert_info["valid from"] = isotime_print( get_kb_item( key + "notBefore" ) ) + " UTC";
	cert_info["valid until"] = isotime_print( get_kb_item( key + "notAfter" ) ) + " UTC";
	cert_info["fingerprint (SHA-1)"] = get_kb_item( key + "fprSHA1" );
	cert_info["fingerprint (SHA-256)"] = get_kb_item( key + "fprSHA256" );
	cert_info["algorithm"] = get_kb_item( key + "algorithm" );
	return NASLString( "\\nCertificate details:\\n", text_format_table( array: cert_info, sep: " | " ) );
}
func check_cert_validity( fprlist, port, vhost, check_for, now, timeframe ){
	var fprlist, port, vhost, check_for, now, timeframe;
	var tmp, fpr, key, valid_end, valid_start, untrusted_authorities, issuer, _pattern;
	if(!fprlist){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#fprlist#-#check_cert_validity" );
		return;
	}
	tmp = split( buffer: fprlist, sep: ",", keep: FALSE );
	fpr = tmp[0];
	if(fpr[0] == "["){
		if(_ssl_funcs_debug){
			display( "A SSL/TLS certificate on port ", port, " (" + vhost + ") is erroneous." );
		}
		return;
	}
	key = "HostDetails/Cert/" + fpr + "/";
	if(check_for == "expired"){
		valid_end = get_kb_item( key + "notAfter" );
		if( valid_end < now ) {
			return key;
		}
		else {
			return;
		}
	}
	if(check_for == "not_valid_yet"){
		valid_start = get_kb_item( key + "notBefore" );
		if( valid_start > now ) {
			return key;
		}
		else {
			return;
		}
	}
	if(check_for == "expire_soon"){
		valid_end = get_kb_item( key + "notAfter" );
		if(valid_end < now){
			return;
		}
		if( valid_end < timeframe ) {
			return key;
		}
		else {
			return;
		}
	}
	if(check_for == "too_long_valid"){
		valid_end = get_kb_item( key + "notAfter" );
		if( valid_end > timeframe ) {
			return key;
		}
		else {
			return;
		}
	}
	if(check_for == "untrusted_ca"){
		untrusted_authorities = make_array( "startcom", "https://www.startcomca.com/index/News/newDetail?date=20171116", "superfish", "https://support.lenovo.com/de/en/product_security/superfish", "edellroot", "https://blog.hboeck.de/archives/876-Superfish-2.0-Dangerous-Certificate-on-Dell-Laptops-breaks-encrypted-HTTPS-Connections.html", "dsd ?test ?provider", "https://blog.hboeck.de/archives/876-Superfish-2.0-Dangerous-Certificate-on-Dell-Laptops-breaks-encrypted-HTTPS-Connections.html", "preact(-| )cli", "none", "acme co", "none", "webpack(-| )dev(-| )server", "none", "localhost", "none" );
		issuer = get_kb_item( key + "issuer" );
		for _pattern in keys( untrusted_authorities ) {
			if(egrep( string: issuer, pattern: _pattern, icase: TRUE )){
				return make_list( issuer,
					 key,
					 untrusted_authorities[_pattern] );
			}
		}
		return;
	}
	return;
}
func _ssl3_tls_hello( port, ciphers, version, extensions, session_id, add_tls_renegotiation_info, add_tls_fallback_scsv, compression_method, alpn_protocol, random, handshake_version, use_extended_ec ){
	var port, ciphers, version, extensions, session_id, add_tls_renegotiation_info, add_tls_fallback_scsv, compression_method, alpn_protocol, random, handshake_version, use_extended_ec;
	var _ciphers, _cipher, clen, time, _random, hello_data, ec_type, tls_kb_vers, hde, hde_len, hdlen, data, hello_len, hello;
	if(!version){
		version = TLS_10;
	}
	if(isnull( add_tls_renegotiation_info )){
		add_tls_renegotiation_info = TRUE;
	}
	if( ciphers ){
		_ciphers = ciphers;
	}
	else {
		_ciphers = sslv3_tls_raw_ciphers["TLS_NULL_WITH_NULL_NULL"] + sslv3_tls_raw_ciphers["TLS_RSA_WITH_NULL_MD5"] + sslv3_tls_raw_ciphers["TLS_RSA_WITH_NULL_SHA"] + sslv3_tls_raw_ciphers["TLS_RSA_EXPORT_WITH_RC4_40_MD5"] + sslv3_tls_raw_ciphers["TLS_RSA_WITH_RC4_128_MD5"] + sslv3_tls_raw_ciphers["TLS_RSA_WITH_RC4_128_SHA"] + sslv3_tls_raw_ciphers["TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"] + sslv3_tls_raw_ciphers["TLS_RSA_WITH_IDEA_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_RSA_WITH_DES_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_RSA_WITH_3DES_EDE_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_DES_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_DES_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_DES_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_DES_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DH_anon_EXPORT_WITH_RC4_40_MD5"] + sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_RC4_128_MD5"] + sslv3_tls_raw_ciphers["TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_DES_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_FORTEZZA_KEA_WITH_NULL_SHA"] + sslv3_tls_raw_ciphers["TLS_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_FORTEZZA_KEA_WITH_RC4_128_SHA or TLS_KRB5_WITH_DES_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_KRB5_WITH_3DES_EDE_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_KRB5_WITH_RC4_128_SHA"] + sslv3_tls_raw_ciphers["TLS_KRB5_WITH_IDEA_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_KRB5_WITH_DES_CBC_MD5"] + sslv3_tls_raw_ciphers["TLS_KRB5_WITH_3DES_EDE_CBC_MD5"] + sslv3_tls_raw_ciphers["TLS_KRB5_WITH_RC4_128_MD5"] + sslv3_tls_raw_ciphers["TLS_KRB5_WITH_IDEA_CBC_MD5"] + sslv3_tls_raw_ciphers["TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA"] + sslv3_tls_raw_ciphers["TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA"] + sslv3_tls_raw_ciphers["TLS_KRB5_EXPORT_WITH_RC4_40_SHA"] + sslv3_tls_raw_ciphers["TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5"] + sslv3_tls_raw_ciphers["TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5"] + sslv3_tls_raw_ciphers["TLS_KRB5_EXPORT_WITH_RC4_40_MD5"] + sslv3_tls_raw_ciphers["TLS_PSK_WITH_NULL_SHA"] + sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_NULL_SHA"] + sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_NULL_SHA"] + sslv3_tls_raw_ciphers["TLS_RSA_WITH_AES_128_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_AES_128_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_AES_128_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_AES_128_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_AES_128_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_AES_128_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_RSA_WITH_AES_256_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_AES_256_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_AES_256_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_AES_256_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_AES_256_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_AES_256_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_RSA_WITH_NULL_SHA256"] + sslv3_tls_raw_ciphers["TLS_RSA_WITH_AES_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_RSA_WITH_AES_256_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_AES_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_AES_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_NULL_SHA (Draft)"] + sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_RC4_128_SHA (Draft)"] + sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_DES_CBC_SHA (Draft)"] + sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA (Draft)"] + sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA (Draft) or TLS_ECDH_ECDSA_EXPORT_WITH_RC4_40_SHA (Draft)"] + sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA (Draft) or TLS_ECDH_ECDSA_EXPORT_WITH_RC4_56_SHA (Draft)"] + sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_NULL_SHA (Draft)"] + sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_RC4_128_SHA (Draft)"] + sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_DES_CBC_SHA (Draft)"] + sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA (Draft) or TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA (Draft)"] + sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_AES_128_CBC_SHA (Draft) or TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA (Draft)"] + sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_AES_256_CBC_SHA (Draft) or TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA (Draft)"] + sslv3_tls_raw_ciphers["TLS_ECDH_RSA_EXPORT_WITH_RC4_40_SHA (Draft) or TLS_SRP_SHA_WITH_AES_128_CBC_SHA (Draft)"] + sslv3_tls_raw_ciphers["TLS_ECDH_RSA_EXPORT_WITH_RC4_56_SHA (Draft) or TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA (Draft)"] + sslv3_tls_raw_ciphers["TLS_ECDH_anon_NULL_WITH_SHA (Draft) or TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA (Draft)"] + sslv3_tls_raw_ciphers["TLS_ECDH_anon_WITH_RC4_128_SHA (Draft) or TLS_SRP_SHA_WITH_AES_256_CBC_SHA (Draft)"] + sslv3_tls_raw_ciphers["TLS_ECDH_anon_WITH_DES_CBC_SHA (Draft) or TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA (Draft)"] + sslv3_tls_raw_ciphers["TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA (Draft) or TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA (Draft)"] + sslv3_tls_raw_ciphers["TLS_ECDH_anon_EXPORT_WITH_DES40_CBC_SHA (Draft1)"] + sslv3_tls_raw_ciphers["TLS_ECDH_anon_EXPORT_WITH_RC4_40_SHA (Draft1)"] + sslv3_tls_raw_ciphers["TLS_ECDH_anon_EXPORT_WITH_DES40_CBC_SHA (Draft2)"] + sslv3_tls_raw_ciphers["TLS_ECDH_anon_EXPORT_WITH_RC4_40_SHA (Draft2)"] + sslv3_tls_raw_ciphers["TLS_RSA_EXPORT1024_WITH_RC4_56_MD5"] + sslv3_tls_raw_ciphers["TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5"] + sslv3_tls_raw_ciphers["TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_RSA_EXPORT1024_WITH_RC4_56_SHA"] + sslv3_tls_raw_ciphers["TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA"] + sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_RC4_128_SHA"] + sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_AES_256_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_AES_256_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_AES_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_AES_256_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_KRB5_WITH_3DES_EDE_CBC_SHA (Draft)"] + sslv3_tls_raw_ciphers["TLS_KRB5_WITH_3DES_EDE_CBC_MD5 (Draft)"] + sslv3_tls_raw_ciphers["TLS_KRB5_WITH_RC4_128_SHA (Draft)"] + sslv3_tls_raw_ciphers["TLS_KRB5_WITH_RC4_128_MD5 (Draft)"] + sslv3_tls_raw_ciphers["TLS_KRB5_WITH_DES_CBC_SHA (Draft)"] + sslv3_tls_raw_ciphers["TLS_KRB5_WITH_DES_CBC_MD5 (Draft)"] + sslv3_tls_raw_ciphers["TLS_KRB5_WITH_AES_128_CBC_SHA (Draft)"] + sslv3_tls_raw_ciphers["TLS_KRB5_WITH_AES_256_CBC_SHA (Draft)"] + sslv3_tls_raw_ciphers["TLS_KRB5_WITH_NULL_SHA (Draft)"] + sslv3_tls_raw_ciphers["TLS_KRB5_WITH_NULL_MD5 (Draft)"] + sslv3_tls_raw_ciphers["TLS_GOSTR341094_WITH_28147_CNT_IMIT (Draft)"] + sslv3_tls_raw_ciphers["TLS_GOSTR341001_WITH_28147_CNT_IMIT (Draft)"] + sslv3_tls_raw_ciphers["TLS_GOSTR341094_WITH_NULL_GOSTR3411 (Draft)"] + sslv3_tls_raw_ciphers["TLS_GOSTR341001_WITH_NULL_GOSTR3411 (Draft)"] + sslv3_tls_raw_ciphers["TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_PSK_WITH_RC4_128_SHA"] + sslv3_tls_raw_ciphers["TLS_PSK_WITH_3DES_EDE_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_PSK_WITH_AES_128_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_PSK_WITH_AES_256_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_RC4_128_SHA"] + sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_AES_128_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_AES_256_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_RC4_128_SHA"] + sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_AES_128_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_AES_256_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_RSA_WITH_SEED_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_SEED_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_SEED_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_SEED_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_SEED_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_SEED_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_RSA_WITH_AES_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_RSA_WITH_AES_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_AES_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_AES_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_AES_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_AES_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_AES_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_AES_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_PSK_WITH_AES_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_PSK_WITH_AES_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_AES_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_AES_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_AES_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_AES_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_PSK_WITH_AES_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_PSK_WITH_AES_256_CBC_SHA384"] + sslv3_tls_raw_ciphers["TLS_PSK_WITH_NULL_SHA256"] + sslv3_tls_raw_ciphers["TLS_PSK_WITH_NULL_SHA384"] + sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_AES_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_AES_256_CBC_SHA384"] + sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_NULL_SHA256"] + sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_NULL_SHA384"] + sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_AES_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_AES_256_CBC_SHA384"] + sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_NULL_SHA256"] + sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_NULL_SHA384"] + sslv3_tls_raw_ciphers["TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_AES_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_AES_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_CHACHA20_POLY1305_SHA256"] + sslv3_tls_raw_ciphers["TLS_AES_128_CCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_AES_128_CCM_8_SHA256"] + sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_NULL_SHA"] + sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_RC4_128_SHA"] + sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_NULL_SHA"] + sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"] + sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_NULL_SHA"] + sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_RC4_128_SHA"] + sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_NULL_SHA"] + sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_RC4_128_SHA"] + sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_ECDH_anon_WITH_NULL_SHA"] + sslv3_tls_raw_ciphers["TLS_ECDH_anon_WITH_RC4_128_SHA"] + sslv3_tls_raw_ciphers["TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_ECDH_anon_WITH_AES_128_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_ECDH_anon_WITH_AES_256_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_SRP_SHA_WITH_AES_128_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_SRP_SHA_WITH_AES_256_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"] + sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"] + sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"] + sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"] + sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_RC4_128_SHA"] + sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA"] + sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384"] + sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_NULL_SHA"] + sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_NULL_SHA256"] + sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_NULL_SHA384"] + sslv3_tls_raw_ciphers["TLS_RSA_WITH_ARIA_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_RSA_WITH_ARIA_256_CBC_SHA384"] + sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384"] + sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384"] + sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384"] + sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384"] + sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_ARIA_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_ARIA_256_CBC_SHA384"] + sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384"] + sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384"] + sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384"] + sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384"] + sslv3_tls_raw_ciphers["TLS_RSA_WITH_ARIA_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_RSA_WITH_ARIA_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_ARIA_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_ARIA_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_PSK_WITH_ARIA_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_PSK_WITH_ARIA_256_CBC_SHA384"] + sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384"] + sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384"] + sslv3_tls_raw_ciphers["TLS_PSK_WITH_ARIA_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_PSK_WITH_ARIA_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384"] + sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"] + sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"] + sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384"] + sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384"] + sslv3_tls_raw_ciphers["TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384"] + sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"] + sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384"] + sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"] + sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"] + sslv3_tls_raw_ciphers["TLS_RSA_WITH_AES_128_CCM"] + sslv3_tls_raw_ciphers["TLS_RSA_WITH_AES_256_CCM"] + sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_AES_128_CCM"] + sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_AES_256_CCM"] + sslv3_tls_raw_ciphers["TLS_RSA_WITH_AES_128_CCM_8"] + sslv3_tls_raw_ciphers["TLS_RSA_WITH_AES_256_CCM_8"] + sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_AES_128_CCM_8"] + sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_AES_256_CCM_8"] + sslv3_tls_raw_ciphers["TLS_PSK_WITH_AES_128_CCM"] + sslv3_tls_raw_ciphers["TLS_PSK_WITH_AES_256_CCM"] + sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_AES_128_CCM"] + sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_AES_256_CCM"] + sslv3_tls_raw_ciphers["TLS_PSK_WITH_AES_128_CCM_8"] + sslv3_tls_raw_ciphers["TLS_PSK_WITH_AES_256_CCM_8"] + sslv3_tls_raw_ciphers["TLS_PSK_DHE_WITH_AES_128_CCM_8"] + sslv3_tls_raw_ciphers["TLS_PSK_DHE_WITH_AES_256_CCM_8"] + sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_AES_128_CCM"] + sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_AES_256_CCM"] + sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8"] + sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8"] + sslv3_tls_raw_ciphers["TLS_ECCPWD_WITH_AES_128_GCM_SHA256 (Draft)"] + sslv3_tls_raw_ciphers["TLS_ECCPWD_WITH_AES_256_GCM_SHA384 (Draft)"] + sslv3_tls_raw_ciphers["TLS_ECCPWD_WITH_AES_128_CCM_SHA256 (Draft)"] + sslv3_tls_raw_ciphers["TLS_ECCPWD_WITH_AES_256_CCM_SHA384 (Draft)"] + sslv3_tls_raw_ciphers["TLS_SHA256_SHA256 (Draft)"] + sslv3_tls_raw_ciphers["TLS_SHA384_SHA384 (Draft)"] + sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (Draft)"] + sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (Draft)"] + sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (Draft)"] + sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"] + sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"] + sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"] + sslv3_tls_raw_ciphers["TLS_PSK_WITH_CHACHA20_POLY1305_SHA256"] + sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256"] + sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256"] + sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256"] + sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384"] + sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256"] + sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256"] + sslv3_tls_raw_ciphers["TLS_RSA_WITH_ESTREAM_SALSA20_SHA1 (Draft)"] + sslv3_tls_raw_ciphers["TLS_RSA_WITH_SALSA20_SHA1 (Draft)"] + sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_ESTREAM_SALSA20_SHA1 (Draft)"] + sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_SALSA20_SHA1 (Draft)"] + sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_ESTREAM_SALSA20_SHA1 (Draft)"] + sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_SALSA20_SHA1 (Draft)"] + sslv3_tls_raw_ciphers["TLS_PSK_WITH_ESTREAM_SALSA20_SHA1 (Draft)"] + sslv3_tls_raw_ciphers["TLS_PSK_WITH_SALSA20_SHA1 (Draft)"] + sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_ESTREAM_SALSA20_SHA1 (Draft)"] + sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_SALSA20_SHA1 (Draft)"] + sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_ESTREAM_SALSA20_SHA1 (Draft)"] + sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_SALSA20_SHA1 (Draft)"] + sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_ESTREAM_SALSA20_SHA1 (Draft)"] + sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_SALSA20_SHA1 (Draft)"] + sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_ESTREAM_SALSA20_SHA1 (Draft)"] + sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_SALSA20_SHA1 (Draft)"] + sslv3_tls_raw_ciphers["TLS_RSA_FIPS_WITH_DES_CBC_SHA (Draft)"] + sslv3_tls_raw_ciphers["TLS_RSA_FIPS_WITH_3DES_EDE_CBC_SHA (Draft)"] + sslv3_tls_raw_ciphers["TLS_RSA_FIPS_WITH_3DES_EDE_CBC_SHA_2 (Draft)"] + sslv3_tls_raw_ciphers["TLS_RSA_FIPS_WITH_DES_CBC_SHA_2 (Draft)"] + sslv3_tls_raw_ciphers["TLS_RSA_WITH_RC2_CBC_MD5 (Draft)"] + sslv3_tls_raw_ciphers["TLS_RSA_WITH_IDEA_CBC_MD5 (Draft)"] + sslv3_tls_raw_ciphers["TLS_RSA_WITH_DES_CBC_MD5 (Draft)"] + sslv3_tls_raw_ciphers["TLS_RSA_WITH_3DES_EDE_CBC_MD5 (Draft)"];
	}
	if(add_tls_renegotiation_info){
		_ciphers += raw_string( 0x00, 0xFF );
	}
	if(add_tls_fallback_scsv){
		_ciphers += raw_string( 0x56, 0x00 );
	}
	clen = data_len( data: _ciphers );
	time = dec2hex( num: unixtime() );
	if( random ) {
		_random = random;
	}
	else {
		_random = raw_string( time ) + raw_string( rand_str( length: 28 ) );
	}
	if(!handshake_version){
		handshake_version = version;
	}
	hello_data = handshake_version + _random;
	if( session_id ) {
		hello_data += raw_string( strlen( session_id ) ) + session_id;
	}
	else {
		hello_data += raw_string( 0x00 );
	}
	hello_data += clen + _ciphers;
	if( compression_method && compression_method != "NULL" ) {
		hello_data += raw_string( 0x02 ) + compression_methods[compression_method] + compression_methods["NULL"];
	}
	else {
		hello_data += raw_string( 0x01 ) + compression_methods["NULL"];
	}
	if( !isnull( use_extended_ec ) ){
		if( use_extended_ec ) {
			ec_type = "elliptic_curves_extended";
		}
		else {
			ec_type = "elliptic_curves";
		}
	}
	else {
		tls_kb_vers = version_kb_string_mapping[version];
		if( isnull( __use_extended_ec[port + "#--#" + tls_kb_vers] ) ){
			use_extended_ec = get_kb_item( "tls_version_get/" + port + "/" + tls_kb_vers + "/extended_ec_used" );
			if(!use_extended_ec){
				use_extended_ec = "no";
			}
			__use_extended_ec[port + "#--#" + tls_kb_vers] = use_extended_ec;
		}
		else {
			use_extended_ec = __use_extended_ec[port + "#--#" + tls_kb_vers];
		}
		if( use_extended_ec && use_extended_ec == "yes" ) {
			ec_type = "elliptic_curves_extended";
		}
		else {
			ec_type = "elliptic_curves";
		}
	}
	if( !extensions ) {
		extensions = make_list( "ec_point_formats",
			 ec_type );
	}
	else {
		extensions = make_list( "ec_point_formats",
			 ec_type,
			 extensions );
	}
	if(version == TLS_12 && !in_array( search: "signature_algorithms", array: extensions )){
		extensions = make_list( extensions,
			 "signature_algorithms" );
	}
	hde = add_ssl_extension( extensions: extensions, alpn_protocol: alpn_protocol );
	hde_len = data_len( data: hde );
	hello_data += hde_len + hde;
	hdlen = data_len( data: hello_data );
	data = raw_string( 0x01, 0x00 ) + hdlen + hello_data;
	hello_len = data_len( data: data );
	hello = raw_string( 0x16 ) + version + hello_len + data;
	return hello;
}
func add_ssl_extension( extensions, alpn_protocol ){
	var extension, alpn_protocol;
	var _e, ecf, ret, _ecs, ecs, alpn, alpn_ret, _alpn, hn, ip, hostname;
	if(!extensions){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#extensions#-#add_ssl_extension" );
		return;
	}
	for _e in extensions {
		if( _e == "ec_point_formats" ){
			ecf = ec_point_formats["uncompressed"] + ec_point_formats["ansiX962_compressed_prime"] + ec_point_formats["ansiX962_compressed_char2"];
			ret += raw_string( 0x00, 0x0b ) + mkword( strlen( ecf ) + 1 ) + raw_string( strlen( ecf ) ) + ecf;
		}
		else {
			if( _e == "elliptic_curves" || _e == "elliptic_curves_extended" ){
				if( _e == "elliptic_curves_extended" ){
					for _ecs in keys( elliptic_curves ) {
						ecs += elliptic_curves[_ecs];
					}
				}
				else {
					ecs = elliptic_curves["secp256r1"] + elliptic_curves["secp384r1"] + elliptic_curves["secp521r1"] + elliptic_curves["sect571r1"] + elliptic_curves["sect571k1"] + elliptic_curves["sect409k1"] + elliptic_curves["sect409r1"] + elliptic_curves["sect283k1"] + elliptic_curves["secp256k1"] + elliptic_curves["sect239k1"] + elliptic_curves["sect233k1"] + elliptic_curves["sect233r1"] + elliptic_curves["secp224k1"] + elliptic_curves["secp224r1"] + elliptic_curves["sect193r1"] + elliptic_curves["secp192k1"] + elliptic_curves["secp192r1"] + elliptic_curves["sect163k1"] + elliptic_curves["sect163r1"] + elliptic_curves["sect163r2"] + elliptic_curves["secp160k1"] + elliptic_curves["secp160r1"] + elliptic_curves["secp160r2"];
				}
				ret += raw_string( 0x00, 0x0a ) + mkword( strlen( ecs ) + 2 ) + data_len( data: ecs ) + ecs;
			}
			else {
				if( _e == "SessionTicket" ){
					ret += raw_string( 0x00, 0x23, 0x00, 0x00 );
				}
				else {
					if( _e == "next_protocol_negotiation" ){
						ret += raw_string( 0x33, 0x74, 0x00, 0x00 );
					}
					else {
						if( _e == "application_layer_protocol_negotiation" ){
							ret += raw_string( 0x00, 0x10 );
							if( alpn_protocol ){
								alpn = application_layer_protocol_negotiation[alpn_protocol];
								if(!alpn){
									continue;
								}
								alpn_ret = mkbyte( strlen( alpn ) ) + alpn;
							}
							else {
								for _alpn in application_layer_protocol_negotiation {
									alpn_ret += mkbyte( strlen( _alpn ) ) + _alpn;
								}
							}
							ret += mkword( strlen( alpn_ret ) + 2 ) + mkword( strlen( alpn_ret ) ) + alpn_ret;
						}
						else {
							if( _e == "status_request" ){
								ret += raw_string( 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00 );
							}
							else {
								if( _e == "signature_algorithms" ){
									ret += raw_string( 0x00, 0x0d, 0x00, 0x22, 0x00, 0x20, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03, 0x01, 0x01 );
								}
								else {
									if( _e == "heartbeat" ){
										ret += raw_string( 0x00, 0x0f, 0x00, 0x01, 0x01 );
									}
									else {
										if( _e == "sni" ){
											hn = get_host_name();
											ip = get_host_ip();
											if(hn != ip){
												hostname = raw_string( 0xFF & 0 ) + mkword( strlen( hn ) ) + hn;
												ret += mkword( 0 ) + mkword( strlen( hostname ) + 2 ) + mkword( strlen( hostname ) ) + hostname;
											}
										}
										else {
											if( _e == "signature_algos" ){
												ret += raw_string( 0x00, 0x0d, 0x00, 0x16, 0x00, 0x14, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x01, 0x04, 0x03, 0x05, 0x03, 0x05, 0x03, 0x02, 0x03, 0x04, 0x02, 0x02, 0x02 );
											}
											else {
												if(_e == "extended_master_secret"){
													ret += raw_string( 0x00, 0x17, 0x00, 0x00 );
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	if(ret){
		return ret;
	}
	return;
}
func data_len( data ){
	var data;
	var data_len;
	if(isnull( data )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#data#-#data_len" );
	}
	data_len = strlen( data );
	return raw_string( data_len / 256, data_len % 256 );
}
func open_ssl_socket( port ){
	var port;
	var soc, starttls_typ, host, req, recv, buf, type, sproto, len;
	var tls_str, starttls, st, search, stls;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#open_ssl_socket" );
		return;
	}
	soc = open_sock_tcp( port: port, transport: ENCAPS_IP );
	if(!soc){
		return FALSE;
	}
	starttls_typ = get_kb_item( "starttls_typ/" + port );
	if(starttls_typ){
		if( starttls_typ == "xmpp-client" ){
			host = get_host_name();
			req = "<stream:stream xmlns='jabber:client' " + "xmlns:stream='http://etherx.jabber.org/streams' " + "version='1.0' " + "to='" + host + "'>";
			send( socket: soc, data: req );
			recv = recv( socket: soc, length: 2048 );
			if(ContainsString( recv, "stream:error" )){
				close( soc );
				return FALSE;
			}
			req = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>";
			send( socket: soc, data: req );
			recv = recv( socket: soc, length: 256 );
			if(!ContainsString( recv, "<proceed" )){
				close( soc );
				return FALSE;
			}
		}
		else {
			if( starttls_typ == "xmpp-server" ){
				host = get_host_name();
				req = "<stream:stream xmlns='jabber:server' " + "xmlns:stream='http://etherx.jabber.org/streams' " + "version='1.0' " + "to='" + host + "'>";
				send( socket: soc, data: req );
				recv = recv( socket: soc, length: 2048 );
				if(ContainsString( recv, "stream:error" )){
					close( soc );
					return FALSE;
				}
				req = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>";
				send( socket: soc, data: req );
				recv = recv( socket: soc, length: 256 );
				if(!ContainsString( recv, "<proceed" )){
					close( soc );
					return FALSE;
				}
			}
			else {
				if( starttls_typ == "ldap" ){
					req = raw_string( 0x30, 0x1d, 0x02, 0x01, 0x01, 0x77, 0x18, 0x80, 0x16, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x31, 0x34, 0x36, 0x36, 0x2e, 0x32, 0x30, 0x30, 0x33, 0x37 );
					send( socket: soc, data: req );
					recv = recv( socket: soc, length: 1024 );
					if(!recv || ord( recv[0] ) != 48){
						close( soc );
						return FALSE;
					}
				}
				else {
					if( starttls_typ == "irc" ){
						send( socket: soc, data: "STARTTLS\r\n" );
						for(;buf = recv_line( socket: soc, length: 2048 );){
							if(ContainsString( buf, ":STARTTLS successful" )){
								return soc;
							}
						}
						close( soc );
						return FALSE;
					}
					else {
						if( starttls_typ == "mysql" ){
							buf = mysql_recv_server_handshake( socket: soc );
							req = raw_string( 0x20, 0x00, 0x00, 0x01, 0x05, 0xae, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );
							send( socket: soc, data: req );
						}
						else {
							if( starttls_typ == "msrdp" ){
								req = raw_string( 0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00 );
								send( socket: soc, data: req );
								buf = recv( socket: soc, length: 19 );
								if(strlen( buf ) != 19){
									close( soc );
									return FALSE;
								}
								type = ord( buf[11] );
								sproto = ord( buf[15] ) | ( ord( buf[16] ) << 8 ) | ( ord( buf[17] ) << 16 ) | ( ord( buf[18] ) << 24 );
								len = ord( buf[13] ) | ( ord( buf[14] ) << 8 );
								if(len != 8){
									close( soc );
									exit( 0 );
								}
								if(type != 2 || ( sproto != 1 && sproto != 2 )){
									return FALSE;
								}
							}
							else {
								tls_str = make_array( "smtp", "220:STARTTLS\r\n", "imap", "A01 OK:A01 STARTTLS\r\n", "pop3", "+OK:STLS\r\n", "ftp", "234:AUTH TLS\r\n", "postgres", "S:" + raw_string( 0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x2F ), "nntp", "382 Continue:STARTTLS\r\n" );
								if(tls_str[starttls_typ]){
									starttls = tls_str[starttls_typ];
									if(starttls_typ == "smtp"){
										for(;!recv( socket: soc, length: 1 );){
											continue;
										}
										send( socket: soc, data: "EHLO " + this_host() + "\r\n" );
									}
									st = split( buffer: starttls, sep: ":", keep: FALSE );
									search = st[0];
									stls = st[1];
									if(isnull( search ) || isnull( stls )){
										return FALSE;
									}
									send( socket: soc, data: stls );
									recv = recv( socket: soc, length: 1024 );
									if(!ContainsString( recv, search )){
										close( soc );
										return FALSE;
									}
								}
							}
						}
					}
				}
			}
		}
	}
	if(!soc){
		return;
	}
	return soc;
}
func ssl2_hello( ciphers, session_id ){
	var ciphers, session_id;
	var version, type, _ciphers, _cipher, clen, sessionid_len, challenge, challenge_len, hello_data, hd_len, hello;
	version = SSL_v2;
	type = raw_string( 0x01 );
	if( ciphers ){
		_ciphers = ciphers;
	}
	else {
		for _cipher in sslv2_raw_ciphers {
			_ciphers += _cipher;
		}
	}
	clen = data_len( data: _ciphers );
	if(!session_id){
		session_id = "";
	}
	sessionid_len = data_len( data: session_id );
	challenge = rand_str( length: 16 );
	challenge_len = data_len( data: challenge );
	hello_data = type + version + clen + sessionid_len + challenge_len + _ciphers + session_id + challenge;
	hd_len = strlen( hello_data );
	hello = raw_string( 0x80 | ( hd_len / 256 ), hd_len % 256 ) + hello_data;
	return hello;
}
func ssl2_recv( soc ){
	var soc;
	var hello, hdr, len, server_hello;
	if(!soc){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#soc#-#ssl2_recv" );
		return;
	}
	hello = ssl2_hello();
	if(!hello){
		return;
	}
	send( socket: soc, data: hello );
	hdr = recv( socket: soc, length: 5, timeout: 5 );
	if(!hdr || strlen( hdr ) != 5){
		return;
	}
	if( ord( hdr[0] ) & 0x80 ){
		len = ( ( ord( hdr[0] ) & 0x7f ) << 8 ) | ord( hdr[1] );
		len -= 3;
	}
	else {
		len = ( ( ord( hdr[0] ) & 0x3f ) << 8 ) | ord( hdr[1] );
		len -= 2;
	}
	if(len < 1){
		return;
	}
	server_hello = hdr + recv( socket: soc, length: len, timeout: 5 );
	if(strlen( server_hello ) < 7){
		return;
	}
	if(ord( server_hello[2] ) == 4 && ord( server_hello[5] ) == 0 && ord( server_hello[6] ) == 2){
		return server_hello;
	}
}
func ssl_recv( socket ){
	var socket;
	var hdr, len, ret;
	if(!socket){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#soc#-#ssl_recv" );
		return;
	}
	hdr = recv( socket: socket, length: 5, timeout: 3 );
	if(!hdr || strlen( hdr ) != 5){
		return;
	}
	if( ord( hdr[1] ) == 3 && ord( hdr[2] ) >= 0 && ord( hdr[2] ) <= 3 ) {
		len = ( ord( hdr[3] ) * 256 + ord( hdr[4] ) );
	}
	else {
		if( ord( hdr[0] ) & 0x80 ){
			len = ( ( ord( hdr[0] ) & 0x7f ) << 8 ) | ord( hdr[1] );
			len -= 3;
		}
		else {
			len = ( ( ord( hdr[0] ) & 0x3f ) << 8 ) | ord( hdr[1] );
			len -= 2;
		}
	}
	if(len < 1){
		return;
	}
	ret = recv( socket: socket, length: len, timeout: 5 );
	if(strlen( ret ) != len){
		return;
	}
	return hdr + ret;
}
func ssl_hello( port, ciphers, version, extensions, session_id, add_tls_renegotiation_info, add_tls_fallback_scsv, compression_method, alpn_protocol, random, handshake_version, use_extended_ec ){
	var port, ciphers, version, extensions, session_id, add_tls_renegotiation_info, add_tls_fallback_scsv, compression_method, alpn_protocol, random, handshake_version, use_extended_ec;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#ssl_hello" );
		return;
	}
	if(!version){
		version = TLS_10;
	}
	if( version == SSL_v2 ) {
		return ssl2_hello( ciphers: ciphers, session_id: session_id );
	}
	else {
		return _ssl3_tls_hello( port: port, ciphers: ciphers, version: version, extensions: extensions, session_id: session_id, add_tls_renegotiation_info: add_tls_renegotiation_info, add_tls_fallback_scsv: add_tls_fallback_scsv, compression_method: compression_method, alpn_protocol: alpn_protocol, random: random, handshake_version: handshake_version, use_extended_ec: use_extended_ec );
	}
}
func search_ssl_record( data, search ){
	var data, search;
	var i, ret_pos, ret, _key;
	if(!data){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#data#-#search_ssl_record" );
		return;
	}
	if(!search){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#search#-#search_ssl_record" );
		return;
	}
	i = 0;
	for(;TRUE;){
		if(ret_pos > strlen( data )){
			return;
		}
		ret = read_ssl_record( data: data, part: i );
		if(!ret){
			return;
		}
		i++;
		ret_pos = ret["pos"];
		for _key in keys( search ) {
			if(!isnull( ret[_key] ) && ret[_key] == search[_key]){
				return ret;
			}
		}
		if(i > 20){
			break;
		}
	}
	return;
}
func read_ssl_record( data, part ){
	var data, part;
	var pos, data_len, record, version, max_len, len, j, typ, e;
	var npn_supported_protocols, alpn_supported_protocols, x;
	var current_cert_len, current_cert, l, i;
	if(!data){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#data#-#read_ssl_record" );
		return;
	}
	if(!part){
		part = 0;
	}
	pos = 0;
	data_len = strlen( data );
	if(data_len < 5){
		return;
	}
	record = make_array();
	record["pos"] = pos;
	if( ord( data[1] ) == 3 && ord( data[2] ) >= 0 && ord( data[2] ) <= 3 ) {
		version = "v3+";
	}
	else {
		version = "v2";
	}
	if( version == "v3+" ){
		record["content_typ"] = ord( data[record["pos"]] );
		record["pos"] += 1;
		record["version"] = raw_string( ord( data[record["pos"]] ), ord( data[record["pos"] + 1] ) );
		record["pos"] += 2;
		record["len"] = ( 5 + getword( blob: data, pos: record["pos"] ) );
		record["pos"] += 2;
		max_len = record["len"];
		if(max_len > data_len){
			return record;
		}
		if( record["content_typ"] == SSLv3_HANDSHAKE ){
			for(i = 0;i < part;i++){
				record["pos"] += 1;
				if(( record["pos"] + 2 ) >= max_len){
					break;
				}
				len = get_3byte_len( data: data, pos: record["pos"] );
				record["pos"] += len + 3;
			}
			if(record["pos"] >= max_len){
				return record;
			}
			record["handshake_typ"] = ord( data[record["pos"]] );
			record["pos"] += 1;
			record["handshake_len"] = get_3byte_len( data: data, pos: record["pos"] );
			record["pos"] += 3;
			if(record["handshake_len"] > max_len){
				return record;
			}
			if( record["handshake_typ"] == SSLv3_SERVER_HELLO ){
				if(( record["pos"] + 38 ) > max_len){
					return record;
				}
				record["handshake_version"] = getword( blob: data, pos: record["pos"] );
				record["pos"] += 2;
				record["time"] = getdword( blob: data, pos: record["pos"] );
				record["pos"] += 4;
				record["random"] = substr( data, record["pos"], record["pos"] + 27 );
				record["pos"] += 28;
				record["session_id_len"] = ord( data[record["pos"]] );
				record["pos"] += 1;
				record["session_id"] = substr( data, record["pos"], record["pos"] + record["session_id_len"] - 1 );
				record["pos"] += record["session_id_len"];
				record["cipher_spec"] = getword( blob: data, pos: record["pos"] );
				record["pos"] += 2;
				record["compression_method"] = ord( data[record["pos"]] );
				record["pos"] += 1;
				if(( record["pos"] + 2 ) > max_len){
					return record;
				}
				record["extensions_len"] = getword( blob: data, pos: record["pos"] );
				record["pos"] += 2;
				if(( record["pos"] + record["extensions_len"] ) > max_len){
					return record;
				}
				for(j = 0;j < record["extensions_len"];j++){
					if(( record["pos"] + j + 4 ) >= max_len){
						break;
					}
					typ = getword( blob: data, pos: record["pos"] + j );
					if( typ == 0x0f ) {
						record["extension_heartbeat_mode"] = ord( data[record["pos"] + j + 4] );
					}
					else {
						if( typ == 0xff01 ) {
							record["extension_renegotiation_info"] = ord( data[record["pos"] + j + 4] );
						}
						else {
							if( typ == 0x23 ) {
								record["extension_session_ticket_tls"] = ord( data[record["pos"] + j + 4] );
							}
							else {
								if( typ == 0x05 ) {
									record["extension_status_request"] = ord( data[record["pos"] + j + 4] );
								}
								else {
									if( typ == 0x0b ){
										record["extension_ec_point_formats_len"] = ord( data[record["pos"] + j + 4] );
										record["extension_ec_point_formats"] = make_list();
										for(e = 1;e <= record["extension_ec_point_formats_len"];e++){
											if(( record["pos"] + j + 4 + e ) > max_len){
												break;
											}
											record["extension_ec_point_formats"] = make_list( record["extension_ec_point_formats"],
												 data[record["pos"] + j + 4 + e] );
										}
									}
									else {
										if( typ == 0x3374 ){
											record["extension_npn_supported"] = TRUE;
											if(ord( data[record["pos"] + j + 3] ) > 0){
												npn_supported_protocols = parse_npn_alpn_prot( data: data, pos: record["pos"], j: j );
												if(is_array( npn_supported_protocols )){
													record["extension_npn_supported_protocols"] = npn_supported_protocols;
												}
											}
										}
										else {
											if( typ == 0x0010 ){
												record["extension_alpn_supported"] = TRUE;
												if(ord( data[record["pos"] + j + 3] ) > 0){
													alpn_supported_protocols = parse_npn_alpn_prot( data: data, pos: record["pos"], j: j, alpn: TRUE );
													if(is_array( alpn_supported_protocols ) && !isnull( alpn_supported_protocols[0] ) && alpn_supported_protocols[0] == alpn_prot){
														record["extension_alpn_supported_protocols"] = alpn_supported_protocols;
													}
												}
											}
											else {
												if(typ == 0x00){
													record["extension_sni"] = TRUE;
												}
											}
										}
									}
								}
							}
						}
					}
				}
				record["pos"] += record["extensions_len"];
				return record;
			}
			else {
				if( record["handshake_typ"] == SSLv3_SERVER_HELLO_DONE ){
					return record;
				}
				else {
					if( record["handshake_typ"] == SSLv3_SERVER_KEY_EXCHANGE ){
						if(( record["pos"] + record["handshake_len"] ) > max_len){
							return record;
						}
						record["key_exchange_data"] = substr( data, record["pos"] - 4, ( record["pos"] + record["handshake_len"] + 3 ) );
						record["pos"] += record["handshake_len"];
						return record;
					}
					else {
						if( record["handshake_typ"] == SSLv3_CERTIFICATE_STATUS ){
							if(( record["pos"] + 4 ) > max_len){
								return record;
							}
							record["cert_status_typ"] = ord( data[record["pos"]] );
							record["pos"] += 1;
							record["cert_status_len"] = get_3byte_len( data: data, pos: record["pos"] );
							record["pos"] += 3;
							if(( record["pos"] + record["cert_status_len"] ) > max_len){
								return record;
							}
							record["cert_status"] = substr( data, record["pos"], ( record["pos"] + record["cert_status_len"] ) - 1 );
							record["pos"] += ( record["cert_status_len"] - 1 );
							return record;
						}
						else {
							if( record["handshake_typ"] == SSLv3_CERTIFICATE ){
								record["certificates_len"] = get_3byte_len( data: data, pos: record["pos"] );
								if(( record["pos"] + record["certificates_len"] ) > max_len){
									return record;
								}
								record["pos"] += 3;
								record["cert_list"] = make_list();
								for(x = 0;x < record["certificates_len"];x++){
									if(( record["pos"] + l ) > record["certificates_len"]){
										return record;
									}
									current_cert_len = get_3byte_len( data: data, pos: ( record["pos"] + l ) );
									current_cert = substr( data, ( record["pos"] + l + 3 ), ( record["pos"] + l + 2 + current_cert_len ) );
									l += ( current_cert_len + 3 );
									if(strlen( current_cert ) == current_cert_len){
										record["cert_list"] = make_list( record["cert_list"],
											 current_cert );
									}
								}
								record["pos"] += record["certificates_len"];
								return record;
							}
							else {
								return record;
							}
						}
					}
				}
			}
		}
		else {
			if( record["content_typ"] == SSLv3_ALERT ){
				if(( record["pos"] + 2 ) > max_len){
					return record;
				}
				record["level"] = ord( data[record["pos"]] );
				record["pos"] += 1;
				record["description"] = ord( data[record["pos"]] );
				record["pos"] += 1;
				return record;
			}
			else {
				if( record["content_typ"] == SSLv3_APPLICATION_DATA ){
					record["data"] = substr( data, record["pos"], record["len"] - 1 );
					return record;
				}
				else {
					return record;
				}
			}
		}
	}
	else {
		if(!record["pos"]){
			record["pos"] = 0;
		}
		if( ord( data[record["pos"]] ) & 0x80 ){
			record["len"] = ( ( ord( data[record["pos"]] ) & 0x7f ) << 8 ) | ord( data[record["pos"] + 1] );
			record["pos"] += 2;
		}
		else {
			record["len"] = ( ( ord( data[record["pos"]] ) & 0x3f ) << 8 ) | ord( data[record["pos"] + 1] );
			record["pos"] += 3;
		}
		if(part > 0){
			return;
		}
		data_len = strlen( data );
		max_len = record["len"] + 2;
		if(max_len > data_len){
			return;
		}
		record["version"] = SSL_v2;
		record["content_typ"] = ord( data[record["pos"]] );
		record["pos"] += 1;
		if(record["content_typ"] == SSLv2_SERVER_HELLO){
			if(( record["pos"] + 4 ) > max_len){
				return record;
			}
			record["session_id_hit"] = ord( data[record["pos"]] );
			record["pos"] += 1;
			record["certificate_typ"] = ord( data[record["pos"]] );
			record["pos"] += 3;
			record["certificate_len"] = getword( blob: data, pos: record["pos"] );
			if(( record["pos"] + 4 ) > max_len){
				return record;
			}
			record["pos"] += 2;
			record["cipher_spec_len"] = getword( blob: data, pos: record["pos"] );
			record["pos"] += 2;
			record["connection_id_len"] = getword( blob: data, pos: record["pos"] );
			if(( record["pos"] + 4 ) > max_len){
				return record;
			}
			record["pos"] += 2;
			if(( record["pos"] + record["certificate_len"] ) > max_len){
				return record;
			}
			record["cert_list"] = make_list( substr( data,
				 record["pos"],
				 ( record["pos"] + record["certificate_len"] - 1 ) ) );
			record["pos"] += record["certificate_len"];
			record["cipher_specs"] = make_list();
			for(i = 0;i < ( record["cipher_spec_len"] / 3 );i++){
				record["cipher_specs"] = make_list( record["cipher_specs"],
					 raw_string( data[record["pos"]],
					 ord( data[record["pos"] + 1] ),
					 ord( data[record["pos"] + 2] ) ) );
				record["pos"] += 3;
				if(( record["pos"] + 2 ) > max_len){
					return record;
				}
			}
			if(( record["pos"] + record["connection_id_len"] ) > max_len){
				return record;
			}
			record["connection_id"] = substr( data, record["pos"], ( record["pos"] + record["connection_id_len"] - 1 ) );
			record["pos"] += record["connection_id_len"];
			return record;
		}
	}
	return;
}
func parse_npn_alpn_prot( data, pos, j, alpn ){
	var data, pos, j, alpn;
	var offset, start, end, protocols_raw, protocols_raw_len, _pos, parsed_protocols, l, protocol;
	if( alpn ) {
		offset = 1;
	}
	else {
		offset = 0;
	}
	start = pos + j + 4 + offset;
	end = start + ord( data[pos + j + 3] );
	protocols_raw = substr( data, start, end );
	protocols_raw_len = strlen( protocols_raw );
	_pos = offset;
	parsed_protocols = make_list();
	for(;_pos < strlen( protocols_raw );){
		l = ord( protocols_raw[_pos] );
		if(l == 0 || ( _pos + l ) > protocols_raw_len){
			break;
		}
		_pos++;
		protocol = substr( protocols_raw, _pos, ( _pos + l ) - 1 );
		_pos += l;
		if(strlen( protocol ) != l){
			continue;
		}
		parsed_protocols = make_list( parsed_protocols,
			 protocol );
	}
	return parsed_protocols;
}
func get_3byte_len( data, pos ){
	var data, pos;
	return ( ord( data[pos] ) << 16 ) | ( ord( data[pos + 1] ) << 8 ) | ord( data[pos + 2] );
}
func get_supported_tls_version( port, min, max ){
	var port, min, max;
	var version_list, _vl;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#get_supported_tls_version" );
		return;
	}
	if(min && min != SSL_v2 && min != SSL_v3 && min != TLS_10 && min != TLS_11 && min != TLS_12){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#get_supported_tls_version(): Unsupported 'min' value passed, accepted constants: SSL_v2, SSL_v3, TLS_10, TLS_11, TLS_12." );
		return;
	}
	if(max && max != SSL_v2 && max != SSL_v3 && max != TLS_10 && max != TLS_11 && max != TLS_12){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#get_supported_tls_version(): Unsupported 'max' value passed, accepted constants: SSL_v2, SSL_v3, TLS_10, TLS_11, TLS_12." );
		return;
	}
	if(!version_list = get_kb_list( "tls_version_get/" + port + "/raw_version" )){
		return;
	}
	for _vl in version_list {
		if( strlen( _vl ) == 1 ) {
			_vl += raw_string( 0x00 );
		}
		else {
			if(strlen( _vl ) == 0){
				_vl = raw_string( 0x00, 0x02 );
			}
		}
		if( min && max ){
			if(_vl >= min && _vl <= max){
				return _vl;
			}
		}
		else {
			if( min ){
				if(_vl >= min){
					return _vl;
				}
			}
			else {
				if( max ){
					if(_vl <= max){
						return _vl;
					}
				}
				else {
					return _vl;
				}
			}
		}
	}
	return;
}
func get_supported_tls_versions( port, min, max ){
	var port, min, max;
	var tmp_version_list, version_list, _vl;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#get_supported_tls_versions" );
		return;
	}
	if(min && min != SSL_v2 && min != SSL_v3 && min != TLS_10 && min != TLS_11 && min != TLS_12){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#get_supported_tls_versions(): Unsupported 'min' value passed, accepted constants: SSL_v2, SSL_v3, TLS_10, TLS_11, TLS_12." );
		return;
	}
	if(max && max != SSL_v2 && max != SSL_v3 && max != TLS_10 && max != TLS_11 && max != TLS_12 && max != TLS_13){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#get_supported_tls_versions(): Unsupported 'max' value passed, accepted constants: SSL_v2, SSL_v3, TLS_10, TLS_11, TLS_12, TLS_13." );
		return;
	}
	if(!tmp_version_list = get_kb_list( "tls_version_get/" + port + "/raw_version" )){
		return;
	}
	version_list = make_list();
	for _vl in tmp_version_list {
		if( strlen( _vl ) == 1 ) {
			_vl += raw_string( 0x00 );
		}
		else {
			if(strlen( _vl ) == 0){
				_vl = raw_string( 0x00, 0x02 );
			}
		}
		if( min && max ){
			if(_vl >= min && _vl <= max){
				version_list = make_list( version_list,
					 _vl );
			}
		}
		else {
			if( min ){
				if(_vl >= min){
					version_list = make_list( version_list,
						 _vl );
				}
			}
			else {
				if( max ){
					if(_vl <= max){
						version_list = make_list( version_list,
							 _vl );
					}
				}
				else {
					version_list = make_list( version_list,
						 _vl );
				}
			}
		}
	}
	return version_list;
}
func tls_ssl_get_port(  ){
	return get_kb_item( "ssl_tls/port" );
}
func tls_ssl_get_ports(  ){
	return get_kb_list( "ssl_tls/port" );
}
func tls_ssl_is_enabled( port ){
	var port;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#tls_ssl_is_enabled" );
		return;
	}
	if(get_port_transport( port ) > ENCAPS_IP){
		return TRUE;
	}
	if(get_kb_item( "tls/supported/" + port )){
		return TRUE;
	}
	return FALSE;
}
func tls_ssl_check_small_cert_key_size( cert, algorithm_name, min_key_size ){
	var cert, algorithm_name, min_key_size;
	var certobj, key_size, algorithm, serial, ret_arr;
	if(!cert){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#cert#-#tls_ssl_check_small_cert_key_size" );
		return NULL;
	}
	if(!algorithm_name){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#algorithm_name#-#tls_ssl_check_small_cert_key_size" );
		return NULL;
	}
	if(isnull( min_key_size )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#min_key_size#-#tls_ssl_check_small_cert_key_size" );
		return NULL;
	}
	if(!certobj = cert_open( base64_decode( str: cert ) )){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#tls_ssl_check_small_cert_key_size(): Failed to open / parse passed certificate." );
		return NULL;
	}
	key_size = cert_query( certobj, "key-size" );
	algorithm = cert_query( certobj, "algorithm-name" );
	serial = cert_query( certobj, "serial" );
	issuer = cert_query( certobj, "issuer" );
	cert_close( certobj );
	if(!key_size){
		return NULL;
	}
	if(!algorithm){
		return NULL;
	}
	if(!issuer){
		return NULL;
	}
	if(egrep( string: algorithm, pattern: algorithm_name, icase: TRUE )){
		if(int( key_size ) < min_key_size){
			ret_arr = make_array();
			ret_arr["key-size"] = key_size;
			ret_arr["algorithm"] = algorithm;
			ret_arr["serial"] = serial;
			ret_arr["issuer"] = issuer;
			return ret_arr;
		}
	}
	return FALSE;
}

