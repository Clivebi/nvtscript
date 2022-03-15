if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105821" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-07-25 12:58:51 +0200 (Mon, 25 Jul 2016)" );
	script_name( "Moxa MGate Detection (HTTP)" );
	script_tag( name: "summary", value: "This script performs HTTP based detection of Moxa MGate" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 8081 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url = "/Overview.html";
buf = http_get_cache( item: url, port: port );
if(!IsMatchRegexp( buf, ">Welcome to MGate.*web console" ) || !ContainsString( buf, "<title>Overview</title>" )){
	exit( 0 );
}
set_kb_item( name: "moxa/mgate/detected", value: TRUE );
set_kb_item( name: "moxa/mgate/http/port", value: port );
buf = str_replace( string: buf, find: "&nbsp;", replace: " " );
lines = split( buf );
version = "unknown";
build = "unknown";
model = "unknown";
for(i = 0;i < max_index( lines );i++){
	if(IsMatchRegexp( lines[i], ">Model( Name)?<" )){
		mod = eregmatch( pattern: ">MGate ([^<]+)<", string: lines[i + 1] );
		if(!isnull( mod[1] )){
			model = mod[1];
		}
	}
	if(ContainsString( lines[i], ">Firmware version<" )){
		vb = eregmatch( pattern: ">([0-9.]+[^ ]+) Build ([0-9]+[^< ]+)<", string: lines[i + 1] );
		if(!isnull( vb[1] )){
			version = vb[1];
			set_kb_item( name: "moxa/mgate/http/" + port + "/concluded", value: vb[0] );
		}
		if(!isnull( vb[2] )){
			build = vb[2];
		}
	}
}
set_kb_item( name: "moxa/mgate/http/" + port + "/model", value: model );
set_kb_item( name: "moxa/mgate/http/" + port + "/version", value: version );
set_kb_item( name: "moxa/mgate/http/" + port + "/build", value: build );
exit( 0 );

