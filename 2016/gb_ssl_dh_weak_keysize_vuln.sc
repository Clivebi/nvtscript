if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106223" );
	script_version( "2021-02-12T06:42:15+0000" );
	script_tag( name: "last_modification", value: "2021-02-12 06:42:15 +0000 (Fri, 12 Feb 2021)" );
	script_tag( name: "creation_date", value: "2016-09-06 12:25:58 +0700 (Tue, 06 Sep 2016)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:N" );
	script_name( "SSL/TLS: Diffie-Hellman Key Exchange Insufficient DH Group Strength Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "SSL and TLS" );
	script_dependencies( "secpod_ssl_ciphers.sc" );
	script_mandatory_keys( "secpod_ssl_ciphers/supported_ciphers", "ssl_tls/port" );
	script_xref( name: "URL", value: "https://weakdh.org/" );
	script_xref( name: "URL", value: "https://weakdh.org/sysadmin.html" );
	script_tag( name: "summary", value: "The SSL/TLS service uses Diffie-Hellman groups with insufficient strength
  (key size < 2048)." );
	script_tag( name: "insight", value: "The Diffie-Hellman group are some big numbers that are used as base for
  the DH computations. They can be, and often are, fixed. The security of the final secret depends on the size
  of these parameters. It was found that 512 and 768 bits to be weak, 1024 bits to be breakable by really
  powerful attackers like governments." );
	script_tag( name: "impact", value: "An attacker might be able to decrypt the SSL/TLS communication offline." );
	script_tag( name: "solution", value: "Deploy (Ephemeral) Elliptic-Curve Diffie-Hellman (ECDHE) or use
  a 2048-bit or stronger Diffie-Hellman group (see the references).

  For Apache Web Servers:
  Beginning with version 2.4.7, mod_ssl will use DH parameters which include primes with lengths of more than 1024 bits." );
	script_tag( name: "vuldetect", value: "Checks the DHE temporary public key size." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "Workaround" );
	exit( 0 );
}
require("mysql.inc.sc");
require("byte_func.inc.sc");
require("misc_func.inc.sc");
require("list_array_func.inc.sc");
require("ssl_funcs.inc.sc");
if(!port = tls_ssl_get_port()){
	exit( 0 );
}
if(!tls_versions = get_supported_tls_versions( port: port, min: SSL_v3, max: TLS_12 )){
	exit( 0 );
}
key_size = 0;
for tlsv in tls_versions {
	if(!SSL_VER = version_kb_string_mapping[tlsv]){
		continue;
	}
	if(!cipherList = get_kb_list( "secpod_ssl_ciphers/" + SSL_VER + "/" + port + "/supported_ciphers" )){
		continue;
	}
	dhe_ciphers = NULL;
	for cipher in cipherList {
		if(IsMatchRegexp( cipher, "^TLS_DHE?_" )){
			dhe_ciphers += sslv3_tls_raw_ciphers[cipher];
		}
	}
	if(isnull( dhe_ciphers )){
		continue;
	}
	hello = ssl_hello( port: port, version: tlsv, ciphers: dhe_ciphers, add_tls_renegotiation_info: FALSE );
	soc = open_ssl_socket( port: port );
	if(!soc){
		exit( 0 );
	}
	send( socket: soc, data: hello );
	hello_done = FALSE;
	for(;!hello_done;){
		data = ssl_recv( socket: soc );
		if(!data){
			close( soc );
			break;
		}
		exch = search_ssl_record( data: data, search: make_array( "handshake_typ", SSLv3_SERVER_KEY_EXCHANGE ) );
		if(exch){
			key_exch_data = exch["key_exchange_data"];
			if(!key_exch_data){
				continue;
			}
			p_len = ( ord( key_exch_data[4] ) << 8 ) + ord( key_exch_data[5] );
			g_len = ( ord( key_exch_data[6 + p_len] ) << 8 ) + ord( key_exch_data[7 + p_len] );
			raw_size = ( ord( key_exch_data[8 + p_len + g_len] ) << 8 ) + ord( key_exch_data[9 + p_len + g_len] );
			key_size = raw_size * 8;
		}
		hd = search_ssl_record( data: data, search: make_array( "handshake_typ", SSLv3_SERVER_HELLO_DONE, "content_typ", SSLv3_ALERT ) );
		if(hd){
			close( soc );
			hello_done = TRUE;
		}
	}
}
if(( key_size != 0 ) && ( key_size < 2048 )){
	report = "Server Temporary Key Size: " + key_size + " bits\n";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

