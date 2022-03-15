if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113251" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-08-22 14:28:44 +0200 (Wed, 22 Aug 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Domoticz Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8081 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Checks if Domoticz Smart Home Software
  is running on the target host." );
	script_xref( name: "URL", value: "http://www.domoticz.com/" );
	exit( 0 );
}
CPE = "cpe:/a:domoticz:domoticz:";
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 8081 );
for location in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	url = location;
	if(location == "/"){
		url = "";
	}
	buf = http_get_cache( port: port, item: location );
	if(IsMatchRegexp( buf, "<title>Domoticz" ) && IsMatchRegexp( buf, "src=[\"\']js/domoticz.js[\"\']" )){
		set_kb_item( name: "domoticz/detected", value: TRUE );
		set_kb_item( name: "domoticz/port", value: port );
		version = "unknown";
		buf = http_get_cache( port: port, item: url + "/json.htm?type=command&param=getversion" );
		ver = eregmatch( string: buf, pattern: "\"version\"[ ]*:[ ]*\"([0-9.]+)\"" );
		if(!isnull( ver[1] )){
			version = ver[1];
			set_kb_item( name: "domoticz/version", value: version );
			concluded = ver[0];
		}
		register_and_report_cpe( app: "Domoticz", ver: version, base: CPE, expr: "([0-9.]+)", concluded: concluded, insloc: location, regPort: port, conclUrl: location );
		exit( 0 );
	}
}
exit( 0 );

