if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108650" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-09-18 12:41:49 +0000 (Wed, 18 Sep 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Magic AirMusic Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The script sends a HTTP request to the remote host and attempts
  to detect the presence of a Magic AirMusic device." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
buf = http_get_cache( item: "/", port: port );
if(!buf){
	exit( 0 );
}
found = 0;
if(ContainsString( buf, "erver: magic iradio" )){
	found++;
}
if(ContainsString( buf, "<title>AirMusic</title>" )){
	found++;
}
if(ContainsString( buf, "SetDevName('AirMusic','" )){
	found++;
}
if(ContainsString( buf, "SWDisp('AirMusic','" )){
	found++;
}
if(egrep( string: buf, pattern: "id=\"(wifi|inp|unfold|fold|sw|swfold|swunfold)_AirMusic\"", icase: FALSE )){
	found++;
}
if(found < 2){
	exit( 0 );
}
version = "unknown";
set_kb_item( name: "magic/airmusic/detected", value: TRUE );
cpe = "cpe:/a:magic:airmusic";
register_product( cpe: cpe, location: "/", port: port, service: "www" );
log_message( data: build_detection_report( app: "Magic AirMusic", version: version, install: "/", cpe: cpe ), port: port );
exit( 0 );

