if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808245" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-07-04 17:44:06 +0530 (Mon, 04 Jul 2016)" );
	script_name( "Option CloudGate Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of Option CloudGate devices." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
res = http_get_cache( item: "/", port: port );
if(( ContainsString( res, "<title>CloudGate</title>" ) && ContainsString( res, "Powered by Cloudgate" ) && ContainsString( res, "js/cg.js" ) ) || ( ContainsString( res, "document.title = \"CloudGate\"" ) && ContainsString( res, "api/replacementui" ) )){
	version = "unknown";
	model = "unknown";
	set_kb_item( name: "option/cloudgate/detected", value: TRUE );
	set_kb_item( name: "option/cloudgate/http/port", value: port );
	set_kb_item( name: "option/cloudgate/http/" + port + "/version", value: version );
	set_kb_item( name: "option/cloudgate/http/" + port + "/model", value: model );
}
exit( 0 );

