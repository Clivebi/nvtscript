if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10874" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_bugtraq_id( 4172 );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Rich Media E-Commerce Stores Sensitive Information Insecurely" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2002 SecurITeam" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://web.archive.org/web/20021218085919/http://www.securiteam.com:80/windowsntfocus/5XP0N0A6AU.html" );
	script_tag( name: "solution", value: "Restrict access to the rtm.log within the web server configuration." );
	script_tag( name: "summary", value: "A security vulnerability in Rich Media's JustAddCommerce allows attackers
  to gain sensitive client information by accessing a log file that is stored in an insecure manner" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/rtm.log";
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( buf, "HttpPost Retry" ) && ContainsString( buf, "checkouthtml" ) && ContainsString( buf, "password" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

