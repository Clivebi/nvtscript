if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802087" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2014-3566" );
	script_bugtraq_id( 70574 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-10-16 17:29:43 +0530 (Thu, 16 Oct 2014)" );
	script_name( "SSL/TLS: SSLv3 Protocol CBC Cipher Suites Information Disclosure Vulnerability (POODLE)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "SSL and TLS" );
	script_dependencies( "secpod_ssl_ciphers.sc", "gb_tls_fallback_scsv_enabled.sc" );
	script_mandatory_keys( "secpod_ssl_ciphers/supported_ciphers", "ssl_tls/port" );
	script_xref( name: "URL", value: "https://www.openssl.org/~bodo/ssl-poodle.pdf" );
	script_xref( name: "URL", value: "https://www.imperialviolet.org/2014/10/14/poodle.html" );
	script_xref( name: "URL", value: "https://www.dfranke.us/posts/2014-10-14-how-poodle-happened.html" );
	script_xref( name: "URL", value: "http://googleonlinesecurity.blogspot.in/2014/10/this-poodle-bites-exploiting-ssl-30.html" );
	script_tag( name: "summary", value: "This host is prone to an information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Evaluate previous collected information about this service." );
	script_tag( name: "insight", value: "The flaw is due to the block cipher padding not being deterministic and not covered by the Message Authentication Code" );
	script_tag( name: "impact", value: "Successful exploitation will allow a  man-in-the-middle attackers gain access to the plain text data stream." );
	script_tag( name: "solution", value: "Possible Mitigations are:

  - Disable SSLv3

  - Disable cipher suites supporting CBC cipher modes

  - Enable TLS_FALLBACK_SCSV if the service is providing TLSv1.0+" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("ssl_funcs.inc.sc");
require("misc_func.inc.sc");
require("list_array_func.inc.sc");
if(!port = tls_ssl_get_port()){
	exit( 0 );
}
if(!tls_versions = get_kb_item( "tls/supported/" + port )){
	exit( 0 );
}
if(!ContainsString( tls_versions, "SSLv3" )){
	exit( 0 );
}
if(!cipherList = get_kb_list( "secpod_ssl_ciphers/sslv3/" + port + "/supported_ciphers" )){
	exit( 0 );
}
if(!in_array( search: "_CBC_", array: cipherList, part_match: TRUE )){
	exit( 0 );
}
if( ContainsString( tls_versions, "TLSv" ) ){
	if(!get_kb_item( "tls_fallback_scsv_supported/" + port )){
		VULN = TRUE;
	}
}
else {
	VULN = TRUE;
}
if(VULN){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

