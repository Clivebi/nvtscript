if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114133" );
	script_version( "2021-08-31T13:01:28+0000" );
	script_tag( name: "last_modification", value: "2021-08-31 13:01:28 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-09-23 15:56:48 +0200 (Mon, 23 Sep 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_cve_id( "CVE-2019-16645" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "GoAhead Server HTTP Header Injection Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_goahead_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "embedthis/goahead/detected" );
	script_tag( name: "summary", value: "Embedthis GoAhead is prone to an HTTP header injection vulnerability." );
	script_tag( name: "insight", value: "For certain pages, Embedthis GoAhead creates links containing a hostname
  obtained from an arbitrary HTTP Host header sent by an attacker." );
	script_tag( name: "impact", value: "An attacker can potentially use this vulnerability in a phishing attack." );
	script_tag( name: "vuldetect", value: "Checks if such a manipulated link can be created." );
	script_tag( name: "affected", value: "At least GoAhead version 2.5.0." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "https://github.com/Ramikan/Vulnerabilities/blob/master/GoAhead%20Web%20server%20HTTP%20Header%20Injection" );
	exit( 0 );
}
CPE = "cpe:/a:embedthis:goahead";
require("http_func.inc.sc");
require("misc_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
get_app_location( cpe: CPE, port: port );
vuln_urls = make_array();
poc_urls = make_list( "/goform/login",
	 "/config/log_off_page.htm",
	 "/" );
for poc_url in poc_urls {
	vt_strings = get_vt_strings();
	host_header = vt_strings["lowercase_rand"];
	req = http_post_put_req( port: port, url: poc_url, data: "testdata" );
	req = ereg_replace( string: req, pattern: "(Host: [^\r\n]+)", replace: "Host: " + host_header );
	res = http_keepalive_send_recv( port: port, data: req );
	if(!res){
		continue;
	}
	if(match = egrep( string: res, pattern: "(^Location:|This document has moved to a new).+" + host_header, icase: TRUE )){
		vuln_urls[poc_url] = chomp( match );
		VULN = TRUE;
	}
}
if(VULN){
	report = "It was possible to inject a host header and create a manipulated link via a HTTP POST-request to:";
	for vuln_url in keys( vuln_urls ) {
		report += "\n\nURL:         " + http_report_vuln_url( port: port, url: vuln_url, url_only: TRUE );
		report += "\nResponse(s): " + vuln_urls[vuln_url];
	}
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

