if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141019" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-04-24 09:33:03 +0700 (Tue, 24 Apr 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Sonos Speaker Detection" );
	script_tag( name: "summary", value: "Detection of Sonos Speaker.

  The script sends a connection request to the server and attempts to detect Sonos Speaker and to extract its
  version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 1400 );
	script_mandatory_keys( "Sonos/banner" );
	script_xref( name: "URL", value: "https://www.sonos.com/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 1400 );
banner = http_get_remote_headers( port: port );
if(!IsMatchRegexp( banner, "Linux UPnP.*Sonos/" )){
	exit( 0 );
}
url = "/xml/device_description.xml";
req = http_get( port: port, item: url );
res = http_keepalive_send_recv( port: port, data: req );
if(!ContainsString( res, "<modelName>" )){
	exit( 0 );
}
mod = eregmatch( pattern: "<modelName>([^<]+)", string: res );
if(!isnull( mod[1] )){
	model = mod[1];
}
version = "unknown";
vers = eregmatch( pattern: "<softwareVersion>([^<]+)", string: res );
if(!isnull( vers[1] )){
	version = str_replace( string: vers[1], find: "-", replace: "." );
	concUrl = url;
}
hw_vers = eregmatch( pattern: "<hardwareVersion>([^<]+)", string: res );
if(!isnull( hw_vers[1] )){
	extra = "Hardware Version:   " + hw_vers[1];
}
set_kb_item( name: "sonos_speaker/detected", value: TRUE );
tmp_mod = tolower( ereg_replace( string: model, pattern: "[ :]", replace: "_" ) );
cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:sonos:" + tmp_mod + ":" );
if(!cpe){
	cpe = "cpe:/a:sonos:" + tmp_mod;
}
register_product( cpe: cpe, location: "/", port: port, service: "www" );
log_message( data: build_detection_report( app: "Sonos Speaker " + model, version: version, install: "/", cpe: cpe, concluded: vers[0], concludedUrl: concUrl, extra: extra ), port: port );
exit( 0 );

