if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802464" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-10-04 10:42:09 +0530 (Thu, 04 Oct 2012)" );
	script_name( "Omnistar Mailer Software Multiple SQL Injection Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/21716/" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2012/Oct/27" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/524301/30/0/threaded" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "insight", value: "The flaw caused by improper validation of bound vulnerable 'id'
  and 'form_id' parameters in responder, preview, pages, navlinks, contacts, register and index modules." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Omnistar Mailer Softwar and is prone multiple
  SQL injection vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to view, add,
  modify or delete information in the back-end database and compromise the application." );
	script_tag( name: "affected", value: "Omnistar Mailer Version 7.2 and prior" );
	script_tag( name: "solution_type", value: "WillNotFix" );
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
for dir in nasl_make_list_unique( "/mailer", "/mailertest", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/admin/index.php" ), port: port );
	if(ContainsString( rcvRes, "<title>OmniStar" ) && ContainsString( rcvRes, ">Email Marketing Software<" )){
		url = NASLString( dir, "/users/register.php?nav_id='" );
		if(http_vuln_check( port: port, url: url, pattern: ">SQL error.*error in your" + " SQL syntax;", check_header: TRUE, extra_check: make_list( "register.php ",
			 "return smtp_validation" ) )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

