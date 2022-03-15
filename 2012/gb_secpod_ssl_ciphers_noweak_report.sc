if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103441" );
	script_version( "2020-03-31T06:57:15+0000" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "last_modification", value: "2020-03-31 06:57:15 +0000 (Tue, 31 Mar 2020)" );
	script_tag( name: "creation_date", value: "2012-03-01 17:16:10 +0100 (Thu, 01 Mar 2012)" );
	script_name( "SSL/TLS: Report Non Weak Cipher Suites" );
	script_category( ACT_GATHER_INFO );
	script_family( "SSL and TLS" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "secpod_ssl_ciphers.sc" );
	script_mandatory_keys( "secpod_ssl_ciphers/nonweak_ciphers", "ssl_tls/port" );
	script_tag( name: "summary", value: "This routine reports all Non Weak SSL/TLS cipher suites accepted by a service." );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("ssl_funcs.inc.sc");
cipherText = "'Non Weak' cipher suites";
if(!port = tls_ssl_get_port()){
	exit( 0 );
}
if(!sup_ssl = get_kb_item( "tls/supported/" + port )){
	exit( 0 );
}
if(ContainsString( sup_ssl, "SSLv3" )){
	sslv3CipherList = get_kb_list( "secpod_ssl_ciphers/sslv3/" + port + "/nonweak_ciphers" );
	if(!isnull( sslv3CipherList )){
		report += cipherText + " accepted by this service via the SSLv3 protocol:\n\n";
		sslv3CipherList = sort( sslv3CipherList );
		for sslv3Cipher in sslv3CipherList {
			report += sslv3Cipher + "\n";
		}
		report += "\n";
	}
}
if(ContainsString( sup_ssl, "TLSv1.0" )){
	tlsv1_0CipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1/" + port + "/nonweak_ciphers" );
	if(!isnull( tlsv1_0CipherList )){
		report += cipherText + " accepted by this service via the TLSv1.0 protocol:\n\n";
		tlsv1_0CipherList = sort( tlsv1_0CipherList );
		for tlsv1_0Cipher in tlsv1_0CipherList {
			report += tlsv1_0Cipher + "\n";
		}
		report += "\n";
	}
}
if(ContainsString( sup_ssl, "TLSv1.1" )){
	tlsv1_1CipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1_1/" + port + "/nonweak_ciphers" );
	if(!isnull( tlsv1_1CipherList )){
		report += cipherText + " accepted by this service via the TLSv1.1 protocol:\n\n";
		tlsv1_1CipherList = sort( tlsv1_1CipherList );
		for tlsv1_1Cipher in tlsv1_1CipherList {
			report += tlsv1_1Cipher + "\n";
		}
		report += "\n";
	}
}
if(ContainsString( sup_ssl, "TLSv1.2" )){
	tlsv1_2CipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1_2/" + port + "/nonweak_ciphers" );
	if(!isnull( tlsv1_2CipherList )){
		report += cipherText + " accepted by this service via the TLSv1.2 protocol:\n\n";
		tlsv1_2CipherList = sort( tlsv1_2CipherList );
		for tlsv1_2Cipher in tlsv1_2CipherList {
			report += tlsv1_2Cipher + "\n";
		}
		report += "\n";
	}
}
if(report){
	log_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

