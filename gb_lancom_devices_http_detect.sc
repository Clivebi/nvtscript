if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143420" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-01-29 07:39:45 +0000 (Wed, 29 Jan 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "LANCOM Device Detection (HTTP)" );
	script_tag( name: "summary", value: "Detection of LANCOM devices.

  This script performs HTTP based detection of LANCOM devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_mandatory_keys( "LANCOM/banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
banner = http_get_remote_headers( port: port );
if(!ContainsString( banner, "Server: LANCOM" )){
	exit( 0 );
}
res = http_get_cache( port: port, item: "/" );
if(ContainsString( res, "\"headerp\">LANCOM" ) || ContainsString( res, "LANCOM Systems Homepage" )){
	set_kb_item( name: "lancom/detected", value: TRUE );
	set_kb_item( name: "lancom/http/detected", value: TRUE );
	set_kb_item( name: "lancom/http/port", value: port );
	set_kb_item( name: "lancom/http/" + port + "/detected", value: TRUE );
	version = "unknown";
	model = "unknown";
	mod = eregmatch( pattern: "\"headerp\">LANCOM ([^ <]+)", string: res );
	if(isnull( mod[1] )){
		mod = eregmatch( pattern: "Server: LANCOM ([^\r\n ]+)[^\r\n]+", string: res );
	}
	if(!isnull( mod[1] )){
		set_kb_item( name: "lancom/http/" + port + "/model", value: mod[1] );
		concluded = "\n    " + mod[0];
	}
	vers = eregmatch( pattern: "Server: LANCOM([A-Za-z0-9()/ +-]+|[A-Za-z0-9()/ +-.]+\\)) ([0-9]+\\.[0-9.]+)[^\r\n]+", string: res );
	if(!isnull( vers[2] )){
		version = vers[2];
		if(!egrep( pattern: vers[2], string: concluded )){
			concluded += "\n    " + vers[0];
		}
	}
	set_kb_item( name: "lancom/http/" + port + "/version", value: version );
	if(concluded){
		set_kb_item( name: "lancom/http/" + port + "/concluded", value: concluded );
	}
}
exit( 0 );

