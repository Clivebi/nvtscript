if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801201" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-04-07 16:20:50 +0200 (Wed, 07 Apr 2010)" );
	script_cve_id( "CVE-2009-4747" );
	script_bugtraq_id( 36609 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "AIOCP 'cp_html2xhtmlbasic.php' Remote File Inclusion Vulnerability" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/53679" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/507030/100/0/threaded" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary
  code in the context of an application." );
	script_tag( name: "affected", value: "All In One Control Panel (AIOCP) 1.4.001 and prior" );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of user-supplied
  input via the 'page' parameter in cp_html2xhtmlbasic.php that allows the
  attackers to execute arbitrary code on the web server." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running All In One Control Panel (AIOCP) and is
  prone to remote file inclusion vulnerability." );
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
for dir in nasl_make_list_unique( "/", "/AIOCP", "/aiocp", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	req = http_get( item: NASLString( dir, "/public/code/cp_dpage.php" ), port: port );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(ContainsString( res, "Powered by Tecnick.com AIOCP" )){
		req = http_get( item: NASLString( dir, "/public/code/cp_html2xhtmlbasic.php?page=", "http://", get_host_ip(), dir, "/public/code/cp_contact_us.php" ), port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(( ContainsString( res, ">Contact us<" ) ) && ( ContainsString( res, ">name<" ) ) && ( ContainsString( res, ">email<" ) )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

