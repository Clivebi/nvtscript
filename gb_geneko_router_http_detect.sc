if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144114" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-06-16 08:27:51 +0000 (Tue, 16 Jun 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Geneko Router Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of Geneko routers." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
req = http_get( port: port, item: "/" );
res = http_send_recv( port: port, data: req );
if(ContainsString( res, "usemap=\"#zaglmap\"" ) && ContainsString( res, "ruter.css" ) && ( ContainsString( res, "Geneko" ) || ContainsString( res, "lib/gwr.js" ) )){
	version = "unknown";
	model = "unknown";
	set_kb_item( name: "geneko/router/detected", value: TRUE );
	set_kb_item( name: "geneko/router/http/detected", value: TRUE );
	set_kb_item( name: "geneko/router/http/port", value: port );
	set_kb_item( name: "geneko/router/http/" + port + "/version", value: version );
	set_kb_item( name: "geneko/router/http/" + port + "/model", value: model );
}
exit( 0 );

