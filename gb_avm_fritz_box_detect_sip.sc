if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108037" );
	script_version( "2021-04-14T08:50:25+0000" );
	script_tag( name: "last_modification", value: "2021-04-14 08:50:25 +0000 (Wed, 14 Apr 2021)" );
	script_tag( name: "creation_date", value: "2017-01-05 13:21:05 +0100 (Thu, 05 Jan 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "AVM FRITZ!Box Detection (SIP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "sip_detection.sc", "sip_detection_tcp.sc" );
	script_mandatory_keys( "sip/banner/available" );
	script_tag( name: "summary", value: "The script attempts to identify an AVM FRITZ!Box via SIP
  banner and tries to extract the model and version number." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("sip.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
infos = sip_get_port_proto( default_port: "5060", default_proto: "udp" );
port = infos["port"];
proto = infos["proto"];
banner = sip_get_banner( port: port, proto: proto );
if(banner && ( ContainsString( banner, "AVM FRITZ" ) || ContainsString( banner, "FRITZ!OS" ) )){
	set_kb_item( name: "avm_fritz_box/detected", value: TRUE );
	set_kb_item( name: "avm_fritz_box/sip/" + proto + "/detected", value: TRUE );
	set_kb_item( name: "avm_fritz_box/sip/" + proto + "/port", value: port );
	set_kb_item( name: "avm_fritz_box/sip/" + proto + "/" + port + "/concluded", value: banner );
	type = "unknown";
	model = "unknown";
	fw_version = "unknown";
	mo = eregmatch( pattern: "AVM FRITZ!Box (Fon WLAN|WLAN)? ?([0-9]+( (v[0-9]+|vDSL|SL|LTE|Cable))?)", string: banner );
	if(!isnull( mo[1] )){
		type = mo[1];
	}
	if(!isnull( mo[2] )){
		model = mo[2];
	}
	fw = eregmatch( pattern: "AVM FRITZ!Box .* ([0-9]+\\.[0-9]+\\.[0-9]+)($| |\\()", string: banner );
	if(!isnull( fw[1] )){
		fw_version = fw[1];
	}
	set_kb_item( name: "avm_fritz_box/sip/" + proto + "/" + port + "/type", value: type );
	set_kb_item( name: "avm_fritz_box/sip/" + proto + "/" + port + "/model", value: model );
	set_kb_item( name: "avm_fritz_box/sip/" + proto + "/" + port + "/firmware_version", value: fw_version );
}
exit( 0 );

