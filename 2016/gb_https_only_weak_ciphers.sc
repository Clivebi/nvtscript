if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108031" );
	script_version( "2021-09-20T09:01:50+0000" );
	script_cve_id( "CVE-2016-2183", "CVE-2016-6329", "CVE-2020-12872" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-20 09:01:50 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-06 16:11:00 +0000 (Wed, 06 Jan 2021)" );
	script_tag( name: "creation_date", value: "2016-12-22 11:00:00 +0100 (Thu, 22 Dec 2016)" );
	script_name( "SSL/TLS: Report Vulnerable Cipher Suites for HTTPS" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "SSL and TLS" );
	script_dependencies( "secpod_ssl_ciphers.sc" );
	script_require_ports( "Services/www", 443 );
	script_mandatory_keys( "secpod_ssl_ciphers/supported_ciphers", "ssl_tls/port" );
	script_xref( name: "URL", value: "https://bettercrypto.org/" );
	script_xref( name: "URL", value: "https://mozilla.github.io/server-side-tls/ssl-config-generator/" );
	script_xref( name: "URL", value: "https://sweet32.info/" );
	script_tag( name: "summary", value: "This routine reports all SSL/TLS cipher suites accepted by a service
  where attack vectors exists only on HTTPS services." );
	script_tag( name: "solution", value: "The configuration of this services should be changed so
  that it does not accept the listed cipher suites anymore.

  Please see the references for more resources supporting you with this task." );
	script_tag( name: "insight", value: "These rules are applied for the evaluation of the vulnerable cipher suites:

  - 64-bit block cipher 3DES vulnerable to the SWEET32 attack (CVE-2016-2183)." );
	script_tag( name: "affected", value: "Services accepting vulnerable SSL/TLS cipher suites via HTTPS." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
cipherText = "'Vulnerable' cipher suites";
port = http_get_port( default: 443, ignore_broken: TRUE, ignore_cgi_disabled: TRUE );
if(get_port_transport( port ) < ENCAPS_SSLv23){
	exit( 0 );
}
sup_ssl = get_kb_item( "tls/supported/" + port );
if(!sup_ssl){
	exit( 0 );
}
if(ContainsString( sup_ssl, "SSLv3" )){
	sslv3CipherList = get_kb_list( "secpod_ssl_ciphers/sslv3/" + port + "/supported_ciphers" );
	if(!isnull( sslv3CipherList )){
		sslv3CipherList = sort( sslv3CipherList );
		for sslv3Cipher in sslv3CipherList {
			if(IsMatchRegexp( sslv3Cipher, "^TLS_.*_3?DES_.*" )){
				sslv3Vuln = TRUE;
				sslv3tmpReport += sslv3Cipher + " (SWEET32)\n";
			}
		}
		if(sslv3Vuln){
			report += cipherText + " accepted by this service via the SSLv3 protocol:\n\n" + sslv3tmpReport + "\n";
		}
	}
}
if(ContainsString( sup_ssl, "TLSv1.0" )){
	tlsv1_0CipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1/" + port + "/supported_ciphers" );
	if(!isnull( tlsv1_0CipherList )){
		tlsv1_0CipherList = sort( tlsv1_0CipherList );
		for tlsv1_0Cipher in tlsv1_0CipherList {
			if(IsMatchRegexp( tlsv1_0Cipher, "^TLS_.*_3?DES_.*" )){
				tlsv1_0Vuln = TRUE;
				tlsv1_0tmpReport += tlsv1_0Cipher + " (SWEET32)\n";
			}
		}
		if(tlsv1_0Vuln){
			report += cipherText + " accepted by this service via the TLSv1.0 protocol:\n\n" + tlsv1_0tmpReport + "\n";
		}
	}
}
if(ContainsString( sup_ssl, "TLSv1.1" )){
	tlsv1_1CipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1_1/" + port + "/supported_ciphers" );
	if(!isnull( tlsv1_1CipherList )){
		tlsv1_1CipherList = sort( tlsv1_1CipherList );
		for tlsv1_1Cipher in tlsv1_1CipherList {
			if(IsMatchRegexp( tlsv1_1Cipher, "^TLS_.*_3?DES_.*" )){
				tlsv1_1Vuln = TRUE;
				tlsv1_1tmpReport += tlsv1_1Cipher + " (SWEET32)\n";
			}
		}
		if(tlsv1_1Vuln){
			report += cipherText + " accepted by this service via the TLSv1.1 protocol:\n\n" + tlsv1_1tmpReport + "\n";
		}
	}
}
if(ContainsString( sup_ssl, "TLSv1.2" )){
	tlsv1_2CipherList = get_kb_list( "secpod_ssl_ciphers/tlsv1_2/" + port + "/supported_ciphers" );
	if(!isnull( tlsv1_2CipherList )){
		tlsv1_2CipherList = sort( tlsv1_2CipherList );
		for tlsv1_2Cipher in tlsv1_2CipherList {
			if(IsMatchRegexp( tlsv1_2Cipher, "^TLS_.*_3?DES_.*" )){
				tlsv1_2Vuln = TRUE;
				tlsv1_2tmpReport += tlsv1_2Cipher + " (SWEET32)\n";
			}
		}
		if(tlsv1_2Vuln){
			report += cipherText + " accepted by this service via the TLSv1.2 protocol:\n\n" + tlsv1_2tmpReport + "\n";
		}
	}
}
if(report){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

