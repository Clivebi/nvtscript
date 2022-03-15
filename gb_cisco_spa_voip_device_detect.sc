if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106216" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-09-01 10:53:52 +0700 (Thu, 01 Sep 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Cisco Small Business VoIP Device Detection (SIP)" );
	script_tag( name: "summary", value: "Detection of Cisco Small Business VoIP Device.

  The script attempts to identify various Cisco Small Business VoIP devices via SIP banner to extract the
  model and version number." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "sip_detection.sc", "sip_detection_tcp.sc" );
	script_mandatory_keys( "sip/banner/available" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("sip.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
infos = sip_get_port_proto( default_port: "5060", default_proto: "udp" );
port = infos["port"];
proto = infos["proto"];
banner = sip_get_banner( port: port, proto: proto );
if(banner && ContainsString( banner, "Cisco/SPA" )){
	version = "unknown";
	mo = eregmatch( pattern: "Cisco\\/(SPA[0-9A-Z]+)", string: banner );
	if( !isnull( mo[1] ) ){
		model = mo[1];
		cpe_model = tolower( model );
		ver = eregmatch( pattern: model + "-([0-9A-Za-z_.]+)", string: banner );
		if(!isnull( ver[1] )){
			version = ereg_replace( string: ver[1], pattern: "\\(([0-9A-Za-z_]+)\\)", replace: ".\\1" );
		}
		set_kb_item( name: "cisco/spa_voip/model", value: model );
		if(version != "unknown"){
			set_kb_item( name: "cisco/spa_voip/version", value: version );
		}
	}
	else {
		model = "Unknown Model";
		cpe_model = "unknown_model";
	}
	cpe = build_cpe( value: tolower( version ), exp: "^([0-9a-z_.]+)", base: "cpe:/o:cisco:" + cpe_model + ":" );
	if(!cpe){
		cpe = "cpe:/o:cisco:" + cpe_model;
	}
	location = port + "/" + proto;
	os_register_and_report( os: "Cisco Small Business " + model + " Firmware", cpe: cpe, banner_type: "SIP server banner", port: port, proto: proto, banner: mo[0], desc: "Cisco Small Business VoIP Device Detection (SIP)", runs_key: "unixoide" );
	register_product( cpe: cpe, port: port, location: location, service: "sip", proto: proto );
	log_message( data: build_detection_report( app: "Cisco Small Business " + model, version: version, install: location, cpe: cpe, concluded: banner ), port: port, proto: proto );
}
exit( 0 );

