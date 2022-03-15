if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805188" );
	script_version( "2020-03-31T06:57:15+0000" );
	script_cve_id( "CVE-2015-4000" );
	script_bugtraq_id( 74733 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-03-31 06:57:15 +0000 (Tue, 31 Mar 2020)" );
	script_tag( name: "creation_date", value: "2015-05-22 13:17:23 +0530 (Fri, 22 May 2015)" );
	script_name( "SSL/TLS: 'DHE_EXPORT' Man in the Middle Security Bypass Vulnerability (LogJam)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "SSL and TLS" );
	script_dependencies( "secpod_ssl_ciphers.sc" );
	script_mandatory_keys( "secpod_ssl_ciphers/supported_ciphers", "ssl_tls/port" );
	script_xref( name: "URL", value: "https://weakdh.org" );
	script_xref( name: "URL", value: "https://weakdh.org/imperfect-forward-secrecy.pdf" );
	script_xref( name: "URL", value: "http://openwall.com/lists/oss-security/2015/05/20/8" );
	script_xref( name: "URL", value: "https://blog.cloudflare.com/logjam-the-latest-tls-vulnerability-explained" );
	script_xref( name: "URL", value: "https://www.openssl.org/blog/blog/2015/05/20/logjam-freak-upcoming-changes" );
	script_tag( name: "summary", value: "This host is accepting 'DHE_EXPORT' cipher suites
  and is prone to man in the middle attack." );
	script_tag( name: "vuldetect", value: "Check previous collected cipher suites saved in the KB." );
	script_tag( name: "insight", value: "Flaw is triggered when handling
  Diffie-Hellman key exchanges defined in the 'DHE_EXPORT' cipher suites." );
	script_tag( name: "impact", value: "Successful exploitation will allow a
  man-in-the-middle attacker to downgrade the security of a TLS session to
  512-bit export-grade cryptography, which is significantly weaker, allowing
  the attacker to more easily break the encryption and monitor or tamper with
  the encrypted stream." );
	script_tag( name: "affected", value: "- Hosts accepting 'DHE_EXPORT' cipher suites

  - OpenSSL version before 1.0.2b and 1.0.1n" );
	script_tag( name: "solution", value: "- Remove support for 'DHE_EXPORT' cipher
  suites from the service

  - If running OpenSSL updateto version 1.0.2b or 1.0.1n or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("ssl_funcs.inc.sc");
cipherText = "'DHE_EXPORT' cipher suites";
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
			if(IsMatchRegexp( sslv3Cipher, "^TLS_DHE?_.*_EXPORT_" )){
				sslv3Vuln = TRUE;
				sslv3tmpReport += sslv3Cipher + "\n";
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
			if(IsMatchRegexp( tlsv1_0Cipher, "^TLS_DHE?_.*_EXPORT_" )){
				tlsv1_0Vuln = TRUE;
				tlsv1_0tmpReport += tlsv1_0Cipher + "\n";
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
			if(IsMatchRegexp( tlsv1_1Cipher, "^TLS_DHE?_.*_EXPORT_" )){
				tlsv1_1Vuln = TRUE;
				tlsv1_1tmpReport += tlsv1_1Cipher + "\n";
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
			if(IsMatchRegexp( tlsv1_2Cipher, "^TLS_DHE?_.*_EXPORT_" )){
				tlsv1_2Vuln = TRUE;
				tlsv1_2tmpReport += tlsv1_2Cipher + "\n";
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

