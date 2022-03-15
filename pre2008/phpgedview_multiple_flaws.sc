if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11982" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "phpGedView Code injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 Noam Rathaus" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade to the latest version of this software." );
	script_tag( name: "summary", value: "The remote host is running phpGedView, a set of CGI scripts which
  parse GEDCOM 5.5 genealogy files and display them on the internet in a format similar to desktop programs.

  There are multiple vulnerabilities in this product :

  - A path disclosure vulnerability, which will give more information about this host to a remote attacker

  - A cross site scripting vulnerability, which may allow an attacker inject malicious HTML code in it

  - A code injection vulnerability, which may allow an attacker to make this server execute arbitrary PHP
  code hosted on a third party website." );
	script_tag( name: "affected", value: "phpGedView version 2.61. Other versions might be affected as well." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
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
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/authentication_index.php?PGV_BASE_DIRECTORY=http://xxxxxxx/";
	if(http_vuln_check( port: port, url: url, pattern: "http://xxxxxxx/authenticate.php" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

