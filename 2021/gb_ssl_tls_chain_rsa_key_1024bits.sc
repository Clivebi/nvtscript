if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150711" );
	script_version( "2021-09-24T07:45:50+0000" );
	script_tag( name: "last_modification", value: "2021-09-24 07:45:50 +0000 (Fri, 24 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-07 10:07:44 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N" );
	script_tag( name: "severity_origin", value: "Greenbone" );
	script_tag( name: "severity_date", value: "2021-09-13 00:00:00 +0000 (Mon, 13 Sep 2020)" );
	script_name( "SSL/TLS: Server Certificate / Certificate in Chain with RSA keys less than 1024 bits" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_category( ACT_GATHER_INFO );
	script_family( "SSL and TLS" );
	script_dependencies( "gb_ssl_tls_cert_chain_get.sc" );
	script_mandatory_keys( "ssl_tls/port", "ssl_tls/cert_chain/extracted" );
	script_tag( name: "summary", value: "The remote SSL/TLS server certificate and/or any of the
  certificates in the certificate chain is using a RSA key with less than 1024 bits." );
	script_tag( name: "vuldetect", value: "Checks the RSA keys size of the server certificate and all
  certificates in chain for a size < 1024 bit." );
	script_tag( name: "insight", value: "SSL/TLS certificates using RSA keys with less than 1024 bits are
  considered unsafe." );
	script_tag( name: "impact", value: "Using certificates with weak RSA key size can lead to
  unauthorized exposure of sensitive information." );
	script_tag( name: "solution", value: "Replace the certificate with a stronger key and reissue the
  certificates it signed." );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/archive/blogs/pki/rsa-keys-under-1024-bits-are-blocked" );
	script_xref( name: "URL", value: "https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final" );
	exit( 0 );
}
require("ssl_funcs.inc.sc");
require("misc_func.inc.sc");
if(!port = tls_ssl_get_port()){
	exit( 0 );
}
if(!server_cert = get_kb_item( "ssl_tls/cert_chain/" + port + "/certs/server_cert" )){
	exit( 0 );
}
if(unsafe_cert = tls_ssl_check_small_cert_key_size( cert: server_cert, algorithm_name: "rsaencryption", min_key_size: 1024 )){
	report = "\n" + unsafe_cert["key-size"] + ":" + unsafe_cert["serial"] + ":" + unsafe_cert["issuer"] + " (Server certificate)";
}
chain = get_kb_list( "ssl_tls/cert_chain/" + port + "/certs/chain" );
for cert in chain {
	if(unsafe_cert = tls_ssl_check_small_cert_key_size( cert: cert, algorithm_name: "rsaencryption", min_key_size: 1024 )){
		report += "\n" + unsafe_cert["key-size"] + ":" + unsafe_cert["serial"] + ":" + unsafe_cert["issuer"] + " (Certificate in chain)";
	}
}
if(report){
	log_message( port: port, data: "The remote SSL/TLS server is using the following certificate(s) with a RSA key with less than 1024 bits (key-size:serial:issuer):\n" + report );
	exit( 0 );
}
exit( 99 );

