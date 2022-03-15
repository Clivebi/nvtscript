if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117274" );
	script_version( "2021-07-19T08:11:48+0000" );
	script_cve_id( "CVE-2011-3389", "CVE-2015-0204" );
	script_tag( name: "last_modification", value: "2021-07-19 08:11:48 +0000 (Mon, 19 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-03-25 10:41:42 +0000 (Thu, 25 Mar 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_name( "SSL/TLS: Deprecated TLSv1.0 and TLSv1.1 Protocol Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SSL and TLS" );
	script_dependencies( "gb_tls_version_get.sc" );
	script_mandatory_keys( "ssl_tls/port" );
	script_tag( name: "summary", value: "It was possible to detect the usage of the deprecated TLSv1.0
  and/or TLSv1.1 protocol on this system." );
	script_tag( name: "vuldetect", value: "Check the used TLS protocols of the services provided by this
  system." );
	script_tag( name: "insight", value: "The TLSv1.0 and TLSv1.1 protocols contain known cryptographic
  flaws like:

  - CVE-2011-3389: Browser Exploit Against SSL/TLS (BEAST)

  - CVE-2015-0204: Factoring Attack on RSA-EXPORT Keys Padding Oracle On Downgraded Legacy
  Encryption (FREAK)" );
	script_tag( name: "impact", value: "An attacker might be able to use the known cryptographic flaws
  to eavesdrop the connection between clients and the service to get access to sensitive data
  transferred within the secured connection.

  Furthermore newly uncovered vulnerabilities in this protocols won't receive security updates
  anymore." );
	script_tag( name: "affected", value: "All services providing an encrypted communication using the
  TLSv1.0 and/or TLSv1.1 protocols." );
	script_tag( name: "solution", value: "It is recommended to disable the deprecated TLSv1.0 and/or
  TLSv1.1 protocols in favor of the TLSv1.2+ protocols. Please see the references for more
  information." );
	script_xref( name: "URL", value: "https://ssl-config.mozilla.org/" );
	script_xref( name: "URL", value: "https://bettercrypto.org/" );
	script_xref( name: "URL", value: "https://datatracker.ietf.org/doc/rfc8996/" );
	script_xref( name: "URL", value: "https://vnhacker.blogspot.com/2011/09/beast.html" );
	script_xref( name: "URL", value: "https://web.archive.org/web/20201108095603/https://censys.io/blog/freak" );
	script_xref( name: "URL", value: "https://www.enisa.europa.eu/publications/algorithms-key-size-and-parameters-report-2014" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("ssl_funcs.inc.sc");
deprecated_and_supported_report = "In addition to TLSv1.2+ the service is also providing the deprecated";
deprecated_only_report = "The service is only providing the deprecated";
cipher_report = "and supports one or more ciphers." + " Those supported ciphers can be found in the 'SSL/TLS: Report Supported Cipher Suites' (OID: 1.3.6.1.4.1.25623.1.0.802067) VT.";
if(!port = tls_ssl_get_port()){
	exit( 0 );
}
if(!ssvs = get_kb_item( "tls/supported/" + port )){
	exit( 0 );
}
if(ContainsString( ssvs, "TLSv1.0" )){
	tlsv10 = TRUE;
}
if(ContainsString( ssvs, "TLSv1.1" )){
	tlsv11 = TRUE;
}
if(ContainsString( ssvs, "TLSv1.2" )){
	tlsv12 = TRUE;
}
if(ContainsString( ssvs, "TLSv1.3" )){
	tlsv13 = TRUE;
}
if( !tlsv12 && !tlsv13 ){
	if( tlsv10 && tlsv11 ){
		security_message( port: port, data: deprecated_only_report + " TLSv1.0 and TLSv1.1 protocols " + cipher_report );
		exit( 0 );
	}
	else {
		if( !tlsv10 && tlsv11 ){
			security_message( port: port, data: deprecated_only_report + " TLSv1.1 protocol " + cipher_report );
			exit( 0 );
		}
		else {
			if(tlsv10 && !tlsv11){
				security_message( port: port, data: deprecated_only_report + " TLSv1.0 protocol " + cipher_report );
				exit( 0 );
			}
		}
	}
}
else {
	if( tlsv10 && tlsv11 ){
		security_message( port: port, data: deprecated_and_supported_report + " TLSv1.0 and TLSv1.1 protocols " + cipher_report );
		exit( 0 );
	}
	else {
		if( !tlsv10 && tlsv11 ){
			security_message( port: port, data: deprecated_and_supported_report + " TLSv1.1 protocol " + cipher_report );
			exit( 0 );
		}
		else {
			if(tlsv10 && !tlsv11){
				security_message( port: port, data: deprecated_and_supported_report + " TLSv1.0 protocol " + cipher_report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

