if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141683" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-11-14 14:38:36 +0700 (Wed, 14 Nov 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Siemens SIMATIC HMI Device Detection (HTTP)" );
	script_tag( name: "summary", value: "This script performs HTTP based detection of Siemens SIMATIC HMI devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
res = http_get_cache( port: port, item: "/start.html" );
if(ContainsString( res, "Device Status of HMI_Panel" ) && ContainsString( res, "Welcome on HMI_Panel" )){
	set_kb_item( name: "simatic_hmi/detected", value: TRUE );
	set_kb_item( name: "simatic_hmi/http/detected", value: TRUE );
	set_kb_item( name: "simatic_hmi/http/port", value: port );
	mod = eregmatch( pattern: "Device Type</b></td><td class=\"sph_td\">([^&;]+)", string: res );
	if(!isnull( mod[1] )){
		set_kb_item( name: "simatic_hmi/http/" + port + "/model", value: chomp( mod[1] ) );
	}
	vers = eregmatch( pattern: "Image version<.*>V([0-9._]+)", string: res );
	if(!isnull( vers[1] )){
		version = str_replace( string: vers[1], find: "_", replace: "." );
		set_kb_item( name: "simatic_hmi/http/" + port + "/fw_version", value: version );
	}
}
exit( 0 );

