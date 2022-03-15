if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108564" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-04-05 09:31:46 +0000 (Fri, 05 Apr 2019)" );
	script_name( "Shade/Troldesh Ransomware Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Malware" );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The remote host seems to be hosting files within hidden directories
  used to spread the Shade/Troldesh ransomware." );
	script_tag( name: "vuldetect", value: "Sends HTTP GET requests to various known Indicator of Compromise (IOC) files within the
  /.well-known/acme-challenge/ and /.well-known/pki-validation/ folders and checks the response." );
	script_tag( name: "insight", value: "In 2019 it was found that unknown threat actors are known to target WordPress and Jommla
  installation via known vulnerabilities with the goal to misuse the target system to host files of the Shade/Troldesh ransomware
  for various hacking and phishing campaings." );
	script_tag( name: "solution", value: "A whole cleanup of the infected system is recommended." );
	script_xref( name: "URL", value: "https://www.zscaler.de/blogs/research/abuse-hidden-well-known-directory-https-sites" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_timeout( 600 );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("dump.inc.sc");
require("misc_func.inc.sc");
iocs = make_array( "error_log", "^\\[[0-9 -:a-zA-Z]+\\] ", "msg.jpg", "This program cannot be run in DOS mode", "msges.jpg", "This program cannot be run in DOS mode", "ssj.jpg", "This program cannot be run in DOS mode", "messg.jpg", "This program cannot be run in DOS mode", "sserv.jpg", "This program cannot be run in DOS mode", "ssj.jpg", "This program cannot be run in DOS mode", "nba1.jpg", "This program cannot be run in DOS mode", "mxr.pdf", "This program cannot be run in DOS mode", "inst.htm", "^<html>.+<iframe src=\"[\"^]+\\.zip\"", "thn.htm", "^<html>.+<iframe src=\"[\"^]+\\.zip\"", "pik.zip", "", "reso.zip", "", "tehnikol.zip", "", "stroi-industr.zip", "", "gkpik.zip", "", "major.zip", "", "rolf.zip", "", "pic.zip", "", "kia.zip", "", "stroi-invest.zip", "" );
report = "";
port = http_get_port( default: 80 );
for dir in make_list( "/.well-known/acme-challenge/",
	 "/.well-known/pki-validation/" ) {
	req = http_get( port: port, item: dir + rand() );
	res = http_keepalive_send_recv( port: port, data: req );
	if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] [0-9]{3}" ) || IsMatchRegexp( res, "^HTTP/1\\.[01] (200|5[0-9]{2})" )){
		continue;
	}
	for ioc in keys( iocs ) {
		pattern = iocs[ioc];
		url = dir + ioc;
		req = http_get( port: port, item: url );
		if( ContainsString( ioc, ".zip" ) ){
			res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
			if(!res || strlen( res ) < 4){
				continue;
			}
			if(substr( res, 0, 3 ) == raw_string( 0x50, 0x4B, 0x03, 0x04 )){
				report += "\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
				VULN = TRUE;
			}
		}
		else {
			res = http_keepalive_send_recv( port: port, data: req );
			if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
				continue;
			}
			res = bin2string( ddata: res );
			if(eregmatch( string: res, pattern: pattern, icase: FALSE )){
				report += "\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
				VULN = TRUE;
			}
		}
	}
}
if(VULN){
	report = "The following IOCs where identified. NOTE: Please take care when opening the files as these might contain malicious code:\n" + report;
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

