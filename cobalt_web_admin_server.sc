if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10793" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Cobalt Web Administration Server Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 SecuriTeam" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 81 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Disable the Cobalt Administration web server if
  you do not use it, or block inbound connections to this port." );
	script_tag( name: "summary", value: "The remote web server is the Cobalt Administration web server." );
	script_tag( name: "impact", value: "This web server enables attackers to configure your Cobalt server
  if they gain access to a valid authentication username and password." );
	script_tag( name: "qod_type", value: "remote_active" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 81 );
url = "/admin";
res = http_get_cache( item: url, port: port );
if(ContainsString( res, "401 Authorization Required" ) && ( ( ContainsString( res, "CobaltServer" ) ) || ( ContainsString( res, "CobaltRQ" ) ) ) && ( ContainsString( res, "WWW-Authenticate: Basic realm=" ) )){
	http_set_is_marked_embedded( port: port );
	report = http_report_vuln_url( port: port, url: url );
	log_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

