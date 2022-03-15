if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106098" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-06-15 17:03:46 +0700 (Wed, 15 Jun 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Siemens SIMATIC S7 Device Detection (HTTP)" );
	script_tag( name: "summary", value: "This script performs HTTP based detection of Siemens SIMATIC S7
devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url = "/Portal/Portal.mwsl?PriNav=Ident";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( res, "alt=\"Siemens\"" ) && ( ContainsString( res, "alt=\"Simatic Controller\"></td>" ) || ContainsString( res, "Title_Area_Name\">S7" ) || ContainsString( res, "title>SIMATIC" ) )){
	mod = eregmatch( pattern: "<title>SIMATIC\\&nbsp;([A-Z]+)?([0-9]+).*<\\/title>", string: res );
	if(!isnull( mod[2] )){
		model = mod[2];
	}
	version = "unknown";
	x = 0;
	lines = split( res );
	for line in lines {
		if(ContainsString( line, "Firmware:" )){
			ver = eregmatch( pattern: ">V.([^<]+)<", string: lines[x + 1] );
			if( !isnull( ver[1] ) ){
				version = ver[1];
				break;
			}
			else {
				ver = eregmatch( pattern: ">V.([^<]+)<", string: lines[x + 5] );
				if(!isnull( ver[1] )){
					version = ver[1];
					break;
				}
			}
		}
		x++;
	}
	x = 0;
	for line in lines {
		if(ContainsString( line, "Order number" )){
			module = eregmatch( pattern: ">([^<]+)", string: lines[x + 1] );
			if(!isnull( module[1] )){
				set_kb_item( name: "simatic_s7/http/module", value: module[1] );
				break;
			}
		}
		x++;
	}
	module_type = eregmatch( pattern: "moduleType\">([^<]+)", string: res );
	if(!isnull( module_type[1] )){
		set_kb_item( name: "simatic_s7/http/modtype", value: module_type[1] );
	}
	set_kb_item( name: "simatic_s7/detected", value: TRUE );
	if(model){
		set_kb_item( name: "simatic_s7/http/model", value: model );
	}
	if(version != "unknown"){
		set_kb_item( name: "simatic_s7/http/" + port + "/version", value: version );
	}
	set_kb_item( name: "simatic_s7/http/port", value: port );
}
exit( 0 );

