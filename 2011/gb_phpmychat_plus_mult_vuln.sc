if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801936" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-05-16 15:25:30 +0200 (Mon, 16 May 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "MyChat Plus Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/17213/" );
	script_xref( name: "URL", value: "http://www.rxtx.nl/webapps-phpmychat-plus-1-93-multiple-vulnerabilities/" );
	script_xref( name: "URL", value: "http://www.l33thackers.com/Thread-webapps-phpMyChat-Plus-1-93-Multiple-Vulnerabilities" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to cause SQL Injection
  attack, gain sensitive information about the database used by the web application
  or can cause arbitrary code execution inside the context of the web application." );
	script_tag( name: "affected", value: "phpMyChat Plus version 1.93." );
	script_tag( name: "insight", value: "The flaws are due to:

  - Improper sanitization of user supplied input through the 'CookieUsername'
  and 'CookieStatus' parameter in Cookie.

  - Improper sanitization of user supplied input through the 'pmc_password'
  parameter in a printable action to avatar.php." );
	script_tag( name: "solution", value: "Upgrade to version 1.94 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is running MyChat Plus and is prone to multiple
  vulnerabilities." );
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
for dir in nasl_make_list_unique( "/plus", "/phpMyChat", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: NASLString( dir, "/index.php" ), port: port );
	if(ContainsString( res, "<TITLE>My WonderfulWideWeb Chat - phpMyChat-Plus</TITLE>" )){
		url = NASLString( dir, "/avatar.php?pmc_password=\"><script>alert(\"XSS-TEST\")</script>" );
		req = http_get( item: url, port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "<script>alert(\"XSS-TEST\")</script>" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}

