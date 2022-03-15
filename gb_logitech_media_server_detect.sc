if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811877" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-10-24 17:24:40 +0530 (Tue, 24 Oct 2017)" );
	script_name( "Logitech SqueezeCenter/Media Server Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "LogitechMediaServer/banner" );
	script_tag( name: "summary", value: "Detection of a Logitech SqueezeCenter/Media Server.

  This script sends a HTTP GET request to the target and try to get the version from the
  response." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 9000 );
banner = http_get_remote_headers( port: port );
if(_banner = egrep( string: banner, pattern: "^Server: Logitech Media Server", icase: TRUE )){
	_banner = chomp( _banner );
	version = "unknown";
	ver = eregmatch( pattern: "Server: Logitech Media Server \\(([0-9.]+)[^)]*\\)", string: _banner );
	if(ver[1]){
		version = ver[1];
	}
	set_kb_item( name: "logitech/squeezecenter/detected", value: TRUE );
	set_kb_item( name: "logitech/squeezecenter/http/detected", value: TRUE );
	set_kb_item( name: "logitech/squeezecenter/http/port", value: port );
	set_kb_item( name: "logitech/squeezecenter/http/" + port + "/detected", value: TRUE );
	set_kb_item( name: "logitech/squeezecenter/http/" + port + "/version", value: version );
	set_kb_item( name: "logitech/squeezecenter/http/" + port + "/concluded", value: _banner );
}
exit( 0 );

