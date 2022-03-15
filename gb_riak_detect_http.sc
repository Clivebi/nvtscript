if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105590" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-03-30 13:30:23 +0200 (Wed, 30 Mar 2016)" );
	script_name( "Basho Riak Detection (HTTP)" );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts to extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 8098 );
	script_mandatory_keys( "MochiWeb/banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 8098 );
banner = http_get_remote_headers( port: port );
if(!ContainsString( banner, "MochiWeb" )){
	exit( 0 );
}
url = "/stats";
buf = http_get_cache( item: url, port: port );
if(!IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) || !ContainsString( buf, "riak_search_version" )){
	exit( 0 );
}
b = split( buffer: buf, sep: "\r\n\r\n", keep: FALSE );
if(!b[1]){
	exit( 0 );
}
values = split( buffer: b[1], sep: ",", keep: FALSE );
for v in values {
	if(ContainsString( v, "riak_search_version" )){
		version = eregmatch( pattern: "\"riak_search_version\":\"([^\"]+)\"", string: v );
		if(!isnull( version[1] )){
			vers = version[1];
		}
	}
	val_rep += v + "\n";
}
cpe = "cpe:/a:basho:riak";
if( vers ) {
	cpe += ":" + vers;
}
else {
	vers = "unknown";
}
register_product( cpe: cpe, location: "/", port: port, service: "www" );
set_kb_item( name: "riad/http/stats", value: val_rep );
set_kb_item( name: "riad/installed", value: TRUE );
report = build_detection_report( app: "Basho Riak", version: vers, install: "/", concluded: version[0], cpe: cpe, extra: "\nStats:" + val_rep + "\n" );
log_message( port: port, data: report );
exit( 0 );

