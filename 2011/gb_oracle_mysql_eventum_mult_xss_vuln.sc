if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801593" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-02-17 16:08:28 +0100 (Thu, 17 Feb 2011)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:S/C:P/I:P/A:P" );
	script_name( "Oracle MySQL Eventum Multiple Cross Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/98423/ZSL-2011-4989.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary
  script code in the browser of an unsuspecting user in the context of the
  affected site. This may let the attacker steal cookie-based authentication
  credentials and launch other attacks." );
	script_tag( name: "affected", value: "MySQL Eventum version 2.2 and 2.3." );
	script_tag( name: "insight", value: "Multiple flaws are due to an error in '/htdocs/list.php',
  '/htdocs/forgot_password.php' and '/htdocs/select_project.php', which is not
  properly validating the input passed to the 'keywords' parameter." );
	script_tag( name: "solution", value: "Upgrade to MySQL Eventum version 2.3.1 or later." );
	script_tag( name: "summary", value: "This host is running Oracle MySQL Eventum and is prone to
  multiple cross site scripting vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/eventum", "/Eventum", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: NASLString( dir, "/htdocs/index.php" ), port: port );
	if(ContainsString( res, ">Login - Eventum<" )){
		url = NASLString( dir, "/htdocs/forgot_password.php/\"><script>alert(\"XSS-ATTACK_TEST\")</script>" );
		req = http_get( item: url, port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "<script>alert(\"XSS-ATTACK_TEST\")</script>" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

