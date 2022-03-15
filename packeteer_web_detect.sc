if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80031" );
	script_version( "2021-03-19T10:09:18+0000" );
	script_tag( name: "last_modification", value: "2021-03-19 10:09:18 +0000 (Fri, 19 Mar 2021)" );
	script_tag( name: "creation_date", value: "2008-10-24 20:15:31 +0200 (Fri, 24 Oct 2008)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Packeteer/Bluecoat Web Management Interface Detection (HTTP)" );
	script_family( "Product detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 nnposter" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "httpd/banner" );
	script_tag( name: "summary", value: "HTTP based detection of the Packeteer Web Management
  Interface." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
req = http_get( item: "/login.htm", port: port );
resp = http_send_recv( port: port, data: req );
if(!resp){
	exit( 0 );
}
server = egrep( pattern: "^Server: *httpd/1\\.", string: resp, icase: TRUE );
cookie = egrep( pattern: "^Set-Cookie: *[^a-z0-9]PScfgstr=", string: resp, icase: TRUE );
if(!server || !cookie){
	exit( 0 );
}
if(!eregmatch( pattern: "PacketShaper Login</title>", string: resp, icase: TRUE )){
	exit( 0 );
}
model = eregmatch( pattern: ">PacketShaper ([0-9]+)<", string: resp );
if(!isnull( model[1] )){
	md = model[1];
}
cpe = "cpe:/h:bluecoat:packetshaper";
if(md){
	cpe += "_" + md;
}
set_kb_item( name: "bluecoat_packetshaper/installed", value: TRUE );
set_kb_item( name: "bluecoat_packetshaper/port", value: port );
set_kb_item( name: "www/" + port + "/packeteer", value: TRUE );
register_product( cpe: cpe, location: "/login.htm", port: port, service: "www" );
log_message( data: build_detection_report( app: "Packeteer/Bluecoat PacketShaper " + md, version: "unknown", install: "/", cpe: cpe, concluded: "Remote probe" ), port: port );
exit( 0 );

