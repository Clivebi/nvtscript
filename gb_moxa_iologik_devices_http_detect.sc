if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106359" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-10-31 15:52:13 +0700 (Mon, 31 Oct 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Moxa ioLogik Devices Detection (HTTP)" );
	script_tag( name: "summary", value: "This script performs HTTP based detection of Moxa ioLogik devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 8080, 9090 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
res = http_get_cache( port: port, item: "/01.htm" );
if(!ContainsString( res, "Server: ioLogik Web Server" )){
	exit( 0 );
}
set_kb_item( name: "moxa/iologik/detected", value: TRUE );
set_kb_item( name: "moxa/iologik/http/port", value: port );
model = "unknown";
version = "unknown";
build = "unknown";
mo = eregmatch( pattern: "Model Name</TD>.*(E[0-9]{4})</TD>", string: res );
if(!isnull( mo[1] )){
	model = mo[1];
}
ver = eregmatch( pattern: "Firmware Version</TD>.*V([0-9.]+)( Build([0-9]+))?", string: res );
if(!isnull( ver[1] )){
	version = ver[1];
	set_kb_item( name: "moxa/iologik/http/" + port + "/concluded", value: ver[0] );
}
if(!isnull( ver[3] )){
	build = ver[3];
}
set_kb_item( name: "moxa/iologik/http/" + port + "/model", value: model );
set_kb_item( name: "moxa/iologik/http/" + port + "/version", value: version );
set_kb_item( name: "moxa/iologik/http/" + port + "/build", value: build );
exit( 0 );

