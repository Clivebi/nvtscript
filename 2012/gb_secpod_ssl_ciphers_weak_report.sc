if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103440" );
	script_version( "2020-11-26T08:02:59+0000" );
	script_cve_id( "CVE-2013-2566", "CVE-2015-2808", "CVE-2015-4000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-11-26 08:02:59 +0000 (Thu, 26 Nov 2020)" );
	script_tag( name: "creation_date", value: "2012-03-01 17:16:10 +0100 (Thu, 01 Mar 2012)" );
	script_name( "SSL/TLS: Report Weak Cipher Suites" );
	script_category( ACT_GATHER_INFO );
	script_family( "SSL and TLS" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "secpod_ssl_ciphers.sc" );
	script_mandatory_keys( "secpod_ssl_ciphers/weak_ciphers", "ssl_tls/port" );
	script_xref( name: "URL", value: "https://www.bsi.bund.de/SharedDocs/Warnmeldungen/DE/CB/warnmeldung_cb-k16-1465_update_6.html" );
	script_xref( name: "URL", value: "https://bettercrypto.org/" );
	script_xref( name: "URL", value: "https://mozilla.github.io/server-side-tls/ssl-config-generator/" );
	script_tag( name: "summary", value: "This routine reports all Weak SSL/TLS cipher suites accepted by a service.

  NOTE: No severity for SMTP services with 'Opportunistic TLS' and weak cipher suites on port 25/tcp is reported.
  If too strong cipher suites are configured for this service the alternative would be to fall back to an even more insecure
  cleartext communication." );
	script_tag( name: "solution", value: "The configuration of this services should be changed so
  that it does not accept the listed weak cipher suites anymore.

  Please see the references for more resources supporting you with this task." );
	script_tag( name: "insight", value: "These rules are applied for the evaluation of the cryptographic strength:

  - RC4 is considered to be weak (CVE-2013-2566, CVE-2015-2808).

  - Ciphers using 64 bit or less are considered to be vulnerable to brute force methods
  and therefore considered as weak (CVE-2015-4000).

  - 1024 bit RSA authentication is considered to be insecure and therefore as weak.

  - Any cipher considered to be secure for only the next 10 years is considered as medium

  - Any other cipher is considered as strong" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("ssl_funcs.inc.sc");
require("misc_func.inc.sc");
require("list_array_func.inc.sc");
require("smtp_func.inc.sc");
require("port_service_func.inc.sc");
cipherText = "'Weak' cipher suites";
if(!port = tls_ssl_get_port()){
	exit( 0 );
}
if(!sup_ssl = get_kb_item( "tls/supported/" + port )){
	exit( 0 );
}
if(ContainsString( sup_ssl, "SSLv3" )){
	sslv3CipherList = get_kb_list( "secpod_ssl_ciphers/sslv3/" + port + "/weak_ciphers" );
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
	tlsv1_0CipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1/" + port + "/weak_ciphers" );
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
	tlsv1_1CipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1_1/" + port + "/weak_ciphers" );
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
	tlsv1_2CipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1_2/" + port + "/weak_ciphers" );
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
	if(port == "25"){
		if(ports = smtp_get_ports( default_port_list: make_list( 25 ) )){
			if(in_array( search: "25", array: ports )){
				tmpreport = "NOTE: No severity for SMTP services with 'Opportunistic TLS' and weak cipher suites on port 25/tcp is reported. ";
				tmpreport += "If too strong cipher suites are configured for this service the alternative would be to fall back to an even more insecure cleartext communication.";
				log_message( port: port, data: tmpreport + "\n\n" + report );
				exit( 0 );
			}
		}
	}
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

