if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813748" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-08-08 13:39:48 +0530 (Wed, 08 Aug 2018)" );
	script_name( "Hughes Broadband Satellite Modems Remote Detection" );
	script_tag( name: "summary", value: "Detection of presence of Hughes Broadband
  Satellite Modem.

  The script attempts to determine if the remote host runs Hughes Broadband
  Satellite Modem from the telnet banner response." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://www.hughes.com/technologies/broadband-satellite-systems/hn-systems" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/telnet", 1953 );
	script_mandatory_keys( "telnet/hughes_network_systems/broadband_satellite_modem/detected" );
	exit( 0 );
}
require("telnet_func.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("dump.inc.sc");
modPort = telnet_get_port( default: 1953 );
if(!banner = telnet_get_banner( port: modPort )){
	exit( 0 );
}
if(ContainsString( banner, "Broadband Satellite" ) && ContainsString( banner, "Hughes Network Systems" )){
	version = "unknown";
	install = modPort + "/tcp";
	model = eregmatch( pattern: "Broadband Satellite ([0-9A-Za-z/]+)", string: banner );
	if(model[1]){
		model = model[1];
	}
	set_kb_item( name: "hughes_broadband_satelite_modem/detected", value: TRUE );
	set_kb_item( name: "hughes_broadband_satelite_modem/model", value: model );
	cpe = "cpe:/a:hughes:broadband_satelite_modem";
	register_product( cpe: cpe, location: install, port: modPort, service: "telnet" );
	log_message( data: build_detection_report( app: "Hughes Broadband Satellite Modem", version: version, install: install, cpe: cpe, concluded: "Hughes Broadband Satellite Modem Version " + version + " and Model " + model ), port: modPort );
}
exit( 0 );

