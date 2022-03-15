if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105018" );
	script_version( "2020-03-31T06:57:15+0000" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "last_modification", value: "2020-03-31 06:57:15 +0000 (Tue, 31 Mar 2020)" );
	script_tag( name: "creation_date", value: "2014-05-06 14:16:10 +0100 (Tue, 06 May 2014)" );
	script_name( "SSL/TLS: Report Perfect Forward Secrecy (PFS) Cipher Suites" );
	script_category( ACT_GATHER_INFO );
	script_family( "SSL and TLS" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "secpod_ssl_ciphers.sc" );
	script_mandatory_keys( "secpod_ssl_ciphers/supported_ciphers", "ssl_tls/port" );
	script_tag( name: "summary", value: "This routine reports all SSL/TLS cipher suites accepted by a service which are supporting Perfect Forward Secrecy (PFS)." );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("ssl_funcs.inc.sc");
cipherText = "Cipher suites supporting Perfect Forward Secrecy (PFS) are accepted by this service via the";
if(!port = tls_ssl_get_port()){
	exit( 0 );
}
if(!sup_ssl = get_kb_item( "tls/supported/" + port )){
	exit( 0 );
}
if(ContainsString( sup_ssl, "SSLv3" )){
	sslv3CipherList = get_kb_list( "secpod_ssl_ciphers/sslv3/" + port + "/supported_ciphers" );
	if(!isnull( sslv3CipherList )){
		sslv3CipherList = sort( sslv3CipherList );
		for sslv3Cipher in sslv3CipherList {
			if(egrep( pattern: "^TLS_(EC)?DHE_", string: sslv3Cipher )){
				sslv3Pfs = TRUE;
				sslv3tmpReport += sslv3Cipher + "\n";
			}
		}
		if(sslv3Pfs){
			report += cipherText + " SSLv3 protocol:\n\n";
			report += sslv3tmpReport;
			report += "\n";
		}
	}
}
if(ContainsString( sup_ssl, "TLSv1.0" )){
	tlsv1_0CipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1/" + port + "/supported_ciphers" );
	if(!isnull( tlsv1_0CipherList )){
		tlsv1_0CipherList = sort( tlsv1_0CipherList );
		for tlsv1_0Cipher in tlsv1_0CipherList {
			if(egrep( pattern: "^TLS_(EC)?DHE_", string: tlsv1_0Cipher )){
				tlsv1_0Pfs = TRUE;
				tlsv1_0tmpReport += tlsv1_0Cipher + "\n";
			}
		}
		if(tlsv1_0Pfs){
			report += cipherText + " TLSv1.0 protocol:\n\n";
			report += tlsv1_0tmpReport;
			report += "\n";
		}
	}
}
if(ContainsString( sup_ssl, "TLSv1.1" )){
	tlsv1_1CipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1_1/" + port + "/supported_ciphers" );
	if(!isnull( tlsv1_1CipherList )){
		tlsv1_1CipherList = sort( tlsv1_1CipherList );
		for tlsv1_1Cipher in tlsv1_1CipherList {
			if(egrep( pattern: "^TLS_(EC)?DHE_", string: tlsv1_1Cipher )){
				tlsv1_1Pfs = TRUE;
				tlsv1_1tmpReport += tlsv1_1Cipher + "\n";
			}
		}
		if(tlsv1_1Pfs){
			report += cipherText + " TLSv1.1 protocol:\n\n";
			report += tlsv1_1tmpReport;
			report += "\n";
		}
	}
}
if(ContainsString( sup_ssl, "TLSv1.2" )){
	tlsv1_2CipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1_2/" + port + "/supported_ciphers" );
	if(!isnull( tlsv1_2CipherList )){
		tlsv1_2CipherList = sort( tlsv1_2CipherList );
		for tlsv1_2Cipher in tlsv1_2CipherList {
			if(egrep( pattern: "^TLS_(EC)?DHE_", string: tlsv1_2Cipher )){
				tlsv1_2Pfs = TRUE;
				tlsv1_2tmpReport += tlsv1_2Cipher + "\n";
			}
		}
		if(tlsv1_2Pfs){
			report += cipherText + " TLSv1.2 protocol:\n\n";
			report += tlsv1_2tmpReport;
			report += "\n";
		}
	}
}
if( report ){
	log_message( port: port, data: report );
	exit( 0 );
}
else {
	set_kb_item( name: "SSL/PFS/no_ciphers", value: TRUE );
	set_kb_item( name: "SSL/PFS/no_ciphers/port", value: port );
	exit( 0 );
}

