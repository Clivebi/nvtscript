if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106084" );
	script_version( "2021-04-14T08:50:25+0000" );
	script_tag( name: "last_modification", value: "2021-04-14 08:50:25 +0000 (Wed, 14 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-05-25 12:53:28 +0700 (Wed, 25 May 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Linknat VOS SoftSwitch Detection (SIP)" );
	script_tag( name: "summary", value: "Detection of Linknat VOS SoftSwitch.

  The script attempts to identify Linknat VOS SoftSwitch via SIP banner to extract the model and version
  number." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "sip_detection.sc", "sip_detection_tcp.sc" );
	script_mandatory_keys( "sip/banner/available" );
	script_xref( name: "URL", value: "http://www.linknat.com" );
	exit( 0 );
}
require("host_details.inc.sc");
require("sip.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
infos = sip_get_port_proto( default_port: "5060", default_proto: "udp" );
port = infos["port"];
proto = infos["proto"];
banner = sip_get_banner( port: port, proto: proto );
if(banner && egrep( pattern: "VOS[0-9]{4}", string: banner )){
	mo = eregmatch( pattern: "(VOS[0-9]{4})", string: banner );
	model = mo[1];
	version = "unknown";
	ver = eregmatch( pattern: "VOS[0-9]{4} V([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)", string: banner );
	if(!isnull( ver[1] )){
		version = ver[1];
	}
	set_kb_item( name: "linknat_vos/detected", value: TRUE );
	set_kb_item( name: "linknat_vos/model", value: model );
	if( version != "unknown" ){
		set_kb_item( name: "linknat_vos/version", value: version );
		cpe = "cpe:/a:linknat:vos:" + tolower( model ) + ":" + version;
	}
	else {
		cpe = "cpe:/a:linknat:vos:" + tolower( model );
	}
	location = port + "/" + proto;
	register_product( cpe: cpe, port: port, location: location, service: "sip", proto: proto );
	log_message( data: build_detection_report( app: "Linknat SoftSwitch " + model, version: version, install: location, cpe: cpe, concluded: banner ), port: port, proto: proto );
}
exit( 0 );

