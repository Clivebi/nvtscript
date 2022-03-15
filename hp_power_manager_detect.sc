if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100456" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-02-03T13:52:45+0000" );
	script_tag( name: "last_modification", value: "2020-02-03 13:52:45 +0000 (Mon, 03 Feb 2020)" );
	script_tag( name: "creation_date", value: "2010-01-20 19:30:24 +0100 (Wed, 20 Jan 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "HP Power Manager Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_goahead_detect.sc" );
	script_mandatory_keys( "embedthis/goahead/detected" );
	script_xref( name: "URL", value: "https://www.hpe.com/" );
	script_tag( name: "summary", value: "This host is running HP Power Manager, an UPS management and monitoring
  utility." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
CPE = "cpe:/a:embedthis:goahead";
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
url = "/CPage/About_English.asp";
buf = http_get_cache( item: url, port: port );
if(ContainsString( buf, "About HP Power Manager" )){
	vers = "unknown";
	version = eregmatch( string: buf, pattern: "HP Power Manager ([0-9.]+)[ ]*([(Build 0-9)]*)", icase: TRUE );
	if(!isnull( version[1] )){
		if( ContainsString( version[2], "Build" ) ){
			build = eregmatch( pattern: "\\(Build ([0-9]+)\\)", string: version[2] );
			vers = version[1] + "." + build[1];
		}
		else {
			vers = version[1];
		}
		concUrl = url;
	}
	set_kb_item( name: "hp_power_manager/detected", value: TRUE );
	cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:hp:power_manager:" );
	if(!cpe){
		cpe = "cpe:/a:hp:power_manager";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "HP Power Manager", version: vers, install: "/", cpe: cpe, concluded: version[0], concludedUrl: concUrl ), port: port );
	exit( 0 );
}
exit( 0 );

