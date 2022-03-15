if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902061" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-06-01 15:40:11 +0200 (Tue, 01 Jun 2010)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "DataTrack System Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 81 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of DataTrack System." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 81 );
res = http_get_cache( port: port, item: "/" );
if(!res){
	exit( 0 );
}
if(!concluded = egrep( string: res, pattern: "(>DataTrack Web Client<|^Server\\s*:\\s*MagnoWare)", icase: TRUE )){
	exit( 0 );
}
concluded = chomp( concluded );
version = "unknown";
install = port + "/tcp";
vers = eregmatch( pattern: "Server\\s*:\\s*MagnoWare/([0-9.]+)", string: res );
if(vers[1]){
	version = vers[1];
	concluded = vers[0];
}
set_kb_item( name: "www/" + port + "/DataTrack_System", value: version );
set_kb_item( name: "datatrack_system/detected", value: TRUE );
register_and_report_cpe( app: "DataTrack System", ver: version, concluded: concluded, base: "cpe:/a:magnoware:datatrack_system:", expr: "([0-9.]+)", insloc: install, regPort: port, regService: "www" );
exit( 0 );

