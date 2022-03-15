if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140685" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-01-15 15:48:28 +0700 (Mon, 15 Jan 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "CommuniGate Pro Detection (HTTP)" );
	script_tag( name: "summary", value: "Detection of CommuniGate Pro.

The script sends a connection request to the server and attempts to detect CommuniGate Pro and to extract its
version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80, 443, 8010 );
	script_mandatory_keys( "CommuniGatePro/banner" );
	script_xref( name: "URL", value: "https://www.communigate.com/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8010 );
banner = http_get_remote_headers( port: port );
if(!ContainsString( banner, "CommuniGatePro/" )){
	exit( 0 );
}
set_kb_item( name: "communigatepro/detected", value: TRUE );
set_kb_item( name: "communigatepro/http/detected", value: TRUE );
set_kb_item( name: "communigatepro/http/port", value: port );
vers = eregmatch( pattern: "CommuniGatePro/([0-9.]+)", string: banner );
if(!isnull( vers[1] )){
	version = vers[1];
	set_kb_item( name: "communigatepro/http/" + port + "/version", value: version );
	set_kb_item( name: "communigatepro/http/" + port + "/concluded", value: vers[0] );
}
exit( 0 );

