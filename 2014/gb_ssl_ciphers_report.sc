if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802067" );
	script_version( "2021-01-21T10:06:42+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-01-21 10:06:42 +0000 (Thu, 21 Jan 2021)" );
	script_tag( name: "creation_date", value: "2014-03-06 17:20:28 +0530 (Thu, 06 Mar 2014)" );
	script_name( "SSL/TLS: Report Supported Cipher Suites" );
	script_category( ACT_GATHER_INFO );
	script_family( "SSL and TLS" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "secpod_ssl_ciphers.sc" );
	script_mandatory_keys( "secpod_ssl_ciphers/supported_ciphers", "secpod_ssl_ciphers/started", "ssl_tls/port" );
	script_tag( name: "summary", value: "This routine reports all SSL/TLS cipher suites accepted by a service.

  As the VT 'SSL/TLS: Check Supported Cipher Suites' (OID: 1.3.6.1.4.1.25623.1.0.900234) might run into a
  timeout the actual reporting of all accepted cipher suites takes place in this VT instead." );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("ssl_funcs.inc.sc");
strongCipherText = "'Strong' cipher suites";
mediumCipherText = "'Medium' cipher suites";
weakCipherText = "'Weak' cipher suites";
nullCipherText = "'Null' cipher suites";
anonCipherText = "'Anonymous' cipher suites";
if(!port = tls_ssl_get_port()){
	exit( 0 );
}
if(!sup_ssl = get_kb_item( "tls/supported/" + port )){
	exit( 0 );
}
if(ContainsString( sup_ssl, "SSLv3" )){
	sslv3StrongCipherList = get_kb_list( "secpod_ssl_ciphers/sslv3/" + port + "/strong_ciphers" );
	sslv3MediumCipherList = get_kb_list( "secpod_ssl_ciphers/sslv3/" + port + "/medium_ciphers" );
	sslv3WeakCipherList = get_kb_list( "secpod_ssl_ciphers/sslv3/" + port + "/weak_ciphers" );
	sslv3NullCipherList = get_kb_list( "secpod_ssl_ciphers/sslv3/" + port + "/null_ciphers" );
	sslv3AnonCipherList = get_kb_list( "secpod_ssl_ciphers/sslv3/" + port + "/anon_ciphers" );
	if( !isnull( sslv3StrongCipherList ) ){
		report += strongCipherText + " accepted by this service via the SSLv3 protocol:\n\n";
		sslv3StrongCipherList = sort( sslv3StrongCipherList );
		for sslv3StrongCipher in sslv3StrongCipherList {
			report += sslv3StrongCipher + "\n";
		}
		report += "\n";
	}
	else {
		report += "No " + strongCipherText + " accepted by this service via the SSLv3 protocol.\n\n";
	}
	if( !isnull( sslv3MediumCipherList ) ){
		report += mediumCipherText + " accepted by this service via the SSLv3 protocol:\n\n";
		sslv3MediumCipherList = sort( sslv3MediumCipherList );
		for sslv3MediumCipher in sslv3MediumCipherList {
			report += sslv3MediumCipher + "\n";
		}
		report += "\n";
	}
	else {
		report += "No " + mediumCipherText + " accepted by this service via the SSLv3 protocol.\n\n";
	}
	if( !isnull( sslv3WeakCipherList ) ){
		report += weakCipherText + " accepted by this service via the SSLv3 protocol:\n\n";
		sslv3WeakCipherList = sort( sslv3WeakCipherList );
		for sslv3WeakCipher in sslv3WeakCipherList {
			report += sslv3WeakCipher + "\n";
		}
		report += "\n";
	}
	else {
		report += "No " + weakCipherText + " accepted by this service via the SSLv3 protocol.\n\n";
	}
	if( !isnull( sslv3NullCipherList ) ){
		report += nullCipherText + " accepted by this service via the SSLv3 protocol:\n\n";
		sslv3NullCipherList = sort( sslv3NullCipherList );
		for sslv3NullCipher in sslv3NullCipherList {
			report += sslv3NullCipher + "\n";
		}
		report += "\n";
	}
	else {
		report += "No " + nullCipherText + " accepted by this service via the SSLv3 protocol.\n\n";
	}
	if( !isnull( sslv3AnonCipherList ) ){
		report += anonCipherText + " accepted by this service via the SSLv3 protocol:\n\n";
		sslv3AnonCipherList = sort( sslv3AnonCipherList );
		for sslv3AnonCipher in sslv3AnonCipherList {
			report += sslv3AnonCipher + "\n";
		}
		report += "\n";
	}
	else {
		report += "No " + anonCipherText + " accepted by this service via the SSLv3 protocol.\n\n";
	}
}
if(ContainsString( sup_ssl, "TLSv1.0" )){
	tlsv1_0StrongCipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1/" + port + "/strong_ciphers" );
	tlsv1_0MediumCipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1/" + port + "/medium_ciphers" );
	tlsv1_0WeakCipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1/" + port + "/weak_ciphers" );
	tlsv1_0NullCipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1/" + port + "/null_ciphers" );
	tlsv1_0AnonCipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1/" + port + "/anon_ciphers" );
	if( !isnull( tlsv1_0StrongCipherList ) ){
		report += strongCipherText + " accepted by this service via the TLSv1.0 protocol:\n\n";
		tlsv1_0StrongCipherList = sort( tlsv1_0StrongCipherList );
		for tlsv1_0StrongCipher in tlsv1_0StrongCipherList {
			report += tlsv1_0StrongCipher + "\n";
		}
		report += "\n";
	}
	else {
		report += "No " + strongCipherText + " accepted by this service via the TLSv1.0 protocol.\n\n";
	}
	if( !isnull( tlsv1_0MediumCipherList ) ){
		report += mediumCipherText + " accepted by this service via the TLSv1.0 protocol:\n\n";
		tlsv1_0MediumCipherList = sort( tlsv1_0MediumCipherList );
		for tlsv1_0MediumCipher in tlsv1_0MediumCipherList {
			report += tlsv1_0MediumCipher + "\n";
		}
		report += "\n";
	}
	else {
		report += "No " + mediumCipherText + " accepted by this service via the TLSv1.0 protocol.\n\n";
	}
	if( !isnull( tlsv1_0WeakCipherList ) ){
		report += weakCipherText + " accepted by this service via the TLSv1.0 protocol:\n\n";
		tlsv1_0WeakCipherList = sort( tlsv1_0WeakCipherList );
		for tlsv1_0WeakCipher in tlsv1_0WeakCipherList {
			report += tlsv1_0WeakCipher + "\n";
		}
		report += "\n";
	}
	else {
		report += "No " + weakCipherText + " accepted by this service via the TLSv1.0 protocol.\n\n";
	}
	if( !isnull( tlsv1_0NullCipherList ) ){
		report += nullCipherText + " accepted by this service via the TLSv1.0 protocol:\n\n";
		tlsv1_0NullCipherList = sort( tlsv1_0NullCipherList );
		for tlsv1_0NullCipher in tlsv1_0NullCipherList {
			report += tlsv1_0NullCipher + "\n";
		}
		report += "\n";
	}
	else {
		report += "No " + nullCipherText + " accepted by this service via the TLSv1.0 protocol.\n\n";
	}
	if( !isnull( tlsv1_0AnonCipherList ) ){
		report += anonCipherText + " accepted by this service via the TLSv1.0 protocol:\n\n";
		tlsv1_0AnonCipherList = sort( tlsv1_0AnonCipherList );
		for tlsv1_0AnonCipher in tlsv1_0AnonCipherList {
			report += tlsv1_0AnonCipher + "\n";
		}
		report += "\n";
	}
	else {
		report += "No " + anonCipherText + " accepted by this service via the TLSv1.0 protocol.\n\n";
	}
}
if(ContainsString( sup_ssl, "TLSv1.1" )){
	tlsv1_1StrongCipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1_1/" + port + "/strong_ciphers" );
	tlsv1_1MediumCipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1_1/" + port + "/medium_ciphers" );
	tlsv1_1WeakCipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1_1/" + port + "/weak_ciphers" );
	tlsv1_1NullCipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1_1/" + port + "/null_ciphers" );
	tlsv1_1AnonCipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1_1/" + port + "/anon_ciphers" );
	if( !isnull( tlsv1_1StrongCipherList ) ){
		report += strongCipherText + " accepted by this service via the TLSv1.1 protocol:\n\n";
		tlsv1_1StrongCipherList = sort( tlsv1_1StrongCipherList );
		for tlsv1_1StrongCipher in tlsv1_1StrongCipherList {
			report += tlsv1_1StrongCipher + "\n";
		}
		report += "\n";
	}
	else {
		report += "No " + strongCipherText + " accepted by this service via the TLSv1.1 protocol.\n\n";
	}
	if( !isnull( tlsv1_1MediumCipherList ) ){
		report += mediumCipherText + " accepted by this service via the TLSv1.1 protocol:\n\n";
		tlsv1_1MediumCipherList = sort( tlsv1_1MediumCipherList );
		for tlsv1_1MediumCipher in tlsv1_1MediumCipherList {
			report += tlsv1_1MediumCipher + "\n";
		}
		report += "\n";
	}
	else {
		report += "No " + mediumCipherText + " accepted by this service via the TLSv1.1 protocol.\n\n";
	}
	if( !isnull( tlsv1_1WeakCipherList ) ){
		report += weakCipherText + " accepted by this service via the TLSv1.1 protocol:\n\n";
		tlsv1_1WeakCipherList = sort( tlsv1_1WeakCipherList );
		for tlsv1_1WeakCipher in tlsv1_1WeakCipherList {
			report += tlsv1_1WeakCipher + "\n";
		}
		report += "\n";
	}
	else {
		report += "No " + weakCipherText + " accepted by this service via the TLSv1.1 protocol.\n\n";
	}
	if( !isnull( tlsv1_1NullCipherList ) ){
		report += nullCipherText + " accepted by this service via the TLSv1.1 protocol:\n\n";
		tlsv1_1NullCipherList = sort( tlsv1_1NullCipherList );
		for tlsv1_1NullCipher in tlsv1_1NullCipherList {
			report += tlsv1_1NullCipher + "\n";
		}
		report += "\n";
	}
	else {
		report += "No " + nullCipherText + " accepted by this service via the TLSv1.1 protocol.\n\n";
	}
	if( !isnull( tlsv1_1AnonCipherList ) ){
		report += anonCipherText + " accepted by this service via the TLSv1.1 protocol:\n\n";
		tlsv1_1AnonCipherList = sort( tlsv1_1AnonCipherList );
		for tlsv1_1AnonCipher in tlsv1_1AnonCipherList {
			report += tlsv1_1AnonCipher + "\n";
		}
		report += "\n";
	}
	else {
		report += "No " + anonCipherText + " accepted by this service via the TLSv1.1 protocol.\n\n";
	}
}
if(ContainsString( sup_ssl, "TLSv1.2" )){
	tlsv1_2StrongCipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1_2/" + port + "/strong_ciphers" );
	tlsv1_2MediumCipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1_2/" + port + "/medium_ciphers" );
	tlsv1_2WeakCipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1_2/" + port + "/weak_ciphers" );
	tlsv1_2NullCipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1_2/" + port + "/null_ciphers" );
	tlsv1_2AnonCipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1_2/" + port + "/anon_ciphers" );
	if( !isnull( tlsv1_2StrongCipherList ) ){
		report += strongCipherText + " accepted by this service via the TLSv1.2 protocol:\n\n";
		tlsv1_2StrongCipherList = sort( tlsv1_2StrongCipherList );
		for tlsv1_2StrongCipher in tlsv1_2StrongCipherList {
			report += tlsv1_2StrongCipher + "\n";
		}
		report += "\n";
	}
	else {
		report += "No " + strongCipherText + " accepted by this service via the TLSv1.2 protocol.\n\n";
	}
	if( !isnull( tlsv1_2MediumCipherList ) ){
		report += mediumCipherText + " accepted by this service via the TLSv1.2 protocol:\n\n";
		tlsv1_2MediumCipherList = sort( tlsv1_2MediumCipherList );
		for tlsv1_2MediumCipher in tlsv1_2MediumCipherList {
			report += tlsv1_2MediumCipher + "\n";
		}
		report += "\n";
	}
	else {
		report += "No " + mediumCipherText + " accepted by this service via the TLSv1.2 protocol.\n\n";
	}
	if( !isnull( tlsv1_2WeakCipherList ) ){
		report += weakCipherText + " accepted by this service via the TLSv1.2 protocol:\n\n";
		tlsv1_2WeakCipherList = sort( tlsv1_2WeakCipherList );
		for tlsv1_2WeakCipher in tlsv1_2WeakCipherList {
			report += tlsv1_2WeakCipher + "\n";
		}
		report += "\n";
	}
	else {
		report += "No " + weakCipherText + " accepted by this service via the TLSv1.2 protocol.\n\n";
	}
	if( !isnull( tlsv1_2NullCipherList ) ){
		report += nullCipherText + " accepted by this service via the TLSv1.2 protocol:\n\n";
		tlsv1_2NullCipherList = sort( tlsv1_2NullCipherList );
		for tlsv1_2NullCipher in tlsv1_2NullCipherList {
			report += tlsv1_2NullCipher + "\n";
		}
		report += "\n";
	}
	else {
		report += "No " + nullCipherText + " accepted by this service via the TLSv1.2 protocol.\n\n";
	}
	if( !isnull( tlsv1_2AnonCipherList ) ){
		report += anonCipherText + " accepted by this service via the TLSv1.2 protocol:\n\n";
		tlsv1_2AnonCipherList = sort( tlsv1_2AnonCipherList );
		for tlsv1_2AnonCipher in tlsv1_2AnonCipherList {
			report += tlsv1_2AnonCipher + "\n";
		}
		report += "\n";
	}
	else {
		report += "No " + anonCipherText + " accepted by this service via the TLSv1.2 protocol.\n\n";
	}
}
if(report){
	log_message( port: port, data: report );
}
exit( 0 );

