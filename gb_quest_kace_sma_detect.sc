if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141135" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-06-01 10:51:22 +0700 (Fri, 01 Jun 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Quest KACE Systems Management Appliance (SMA) Detection" );
	script_tag( name: "summary", value: "Detection of Quest KACE Systems Management Appliance (SMA).

  The script sends a connection request to the server and attempts to detect Quest KACE Systems Management
  Appliance (SMA) and to extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "KACE-Appliance/banner" );
	script_require_ports( "Services/www", 80, 443 );
	script_xref( name: "URL", value: "https://www.quest.com/kace/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
banner = http_get_remote_headers( port: port );
if(!IsMatchRegexp( banner, "X-(Dell)?KACE-Appliance" )){
	exit( 0 );
}
mod = eregmatch( pattern: "X-(Dell)?KACE-Appliance: (K[0-9]+)", string: banner, icase: TRUE );
if(!isnull( mod[2] )){
	concluded = mod[0];
	model = toupper( mod[2] );
	set_kb_item( name: "quest_kace_sma/model", value: model );
}
vers = eregmatch( pattern: "X-(Dell)?KACE-Version: ([0-9.]+)", string: banner, icase: TRUE );
if(!isnull( vers[2] )){
	if(concluded){
		concluded += "\n";
	}
	concluded += vers[0];
	version = vers[2];
}
set_kb_item( name: "quest_kace_sma/detected", value: TRUE );
cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:quest:kace_systems_management_appliance:" );
if(!cpe){
	cpe = "cpe:/a:quest:kace_systems_management_appliance";
}
register_product( cpe: cpe, location: "/", port: port, service: "www" );
log_message( data: build_detection_report( app: "Quest KACE Systems Management Appliance " + model, version: version, install: "/", cpe: cpe, concluded: concluded ), port: port );
exit( 0 );

