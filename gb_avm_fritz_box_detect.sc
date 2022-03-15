if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103910" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2014-02-19 13:21:05 +0100 (Wed, 19 Feb 2014)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "AVM FRITZ!Box Detection Consolidation" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_avm_fritz_box_detect_http.sc", "gb_avm_fritz_box_detect_sip.sc", "gb_avm_fritz_box_detect_upnp.sc", "gb_avm_fritz_box_detect_ftp.sc" );
	script_mandatory_keys( "avm_fritz_box/detected" );
	script_tag( name: "summary", value: "The script reports a detected AVM FRITZ!Box including the model,
  exposed services and a possible gathered version of the FRITZ!OS." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!get_kb_item( "avm_fritz_box/detected" )){
	exit( 0 );
}
SCRIPT_DESC = "AVM FRITZ!Box Version Detection Consolidation";
detected_type = "unknown";
detected_model = "unknown";
detected_firmware = "unknown";
os_cpe_firmware = "unknown";
report_firmware = "unknown";
for source in make_list( "sip/tcp",
	 "sip/udp",
	 "upnp",
	 "ftp",
	 "http" ) {
	type_list = get_kb_list( "avm_fritz_box/" + source + "/*/type" );
	for type in type_list {
		if(type != "unknown" && detected_type == "unknown"){
			detected_type = type;
			set_kb_item( name: "avm/fritz/type", value: type );
		}
	}
	model_list = get_kb_list( "avm_fritz_box/" + source + "/*/model" );
	for model in model_list {
		if(model != "unknown" && detected_model == "unknown"){
			detected_model = model;
			set_kb_item( name: "avm/fritz/model", value: model );
		}
	}
	firmware_list = get_kb_list( "avm_fritz_box/" + source + "/*/firmware_version" );
	for firmware in firmware_list {
		if(firmware != "unknown" && detected_firmware == "unknown"){
			detected_firmware = firmware;
			set_kb_item( name: "avm/fritz/firmware_version", value: firmware );
		}
	}
}
if(detected_firmware != "unknown"){
	_fw = split( buffer: detected_firmware, sep: ".", keep: TRUE );
	if(max_index( _fw ) == 3){
		os_cpe_firmware = _fw[1] + _fw[2];
		os_cpe_firmware = ereg_replace( string: os_cpe_firmware, pattern: "^0", replace: "" );
	}
	if( os_cpe_firmware != "unknown" ) {
		report_firmware = os_cpe_firmware + " (" + detected_firmware + ")";
	}
	else {
		report_firmware = detected_firmware;
	}
}
os_app = "AVM FRITZ!OS";
os_cpe = build_cpe( value: os_cpe_firmware, exp: "^([0-9.]+)", base: "cpe:/o:avm:fritz%21_os:" );
app_cpe = build_cpe( value: os_cpe_firmware, exp: "^([0-9.]+)", base: "cpe:/a:avm:fritz%21box:" );
if( !os_cpe ){
	os_cpe = "cpe:/o:avm:fritz%21_os";
	app_cpe = "cpe:/a:avm:fritz%21box";
	os_register_and_report( os: os_app, cpe: os_cpe, desc: SCRIPT_DESC, runs_key: "unixoide" );
}
else {
	os_register_and_report( os: os_app + " " + report_firmware, cpe: os_cpe, desc: SCRIPT_DESC, runs_key: "unixoide" );
}
if( detected_model != "unknown" ){
	cpe_model = str_replace( string: tolower( detected_model ), find: " ", replace: "_" );
	hw_cpe = "cpe:/h:avm:fritzbox:" + cpe_model;
}
else {
	hw_cpe = "cpe:/h:avm:fritzbox";
}
hw_app = "AVM FRITZ!Box";
if(detected_type != "unknown"){
	hw_app += " " + detected_type;
}
if(detected_model != "unknown"){
	hw_app += " " + detected_model;
}
location = "/";
if(http_port = get_kb_list( "avm_fritz_box/http/port" )){
	for port in http_port {
		extra += "HTTP(s) on port " + port + "/tcp\n";
		register_product( cpe: hw_cpe, location: location, port: port, service: "www" );
		register_product( cpe: os_cpe, location: location, port: port, service: "www" );
		register_product( cpe: app_cpe, location: location, port: port, service: "www" );
	}
}
if(sip_port = get_kb_list( "avm_fritz_box/sip/tcp/port" )){
	for port in sip_port {
		concluded = get_kb_item( "avm_fritz_box/sip/tcp/" + port + "/concluded" );
		extra += "SIP on port " + port + "/tcp\nBanner: " + concluded + "\n";
		register_product( cpe: hw_cpe, location: location, port: port, service: "sip" );
		register_product( cpe: os_cpe, location: location, port: port, service: "sip" );
		register_product( cpe: app_cpe, location: location, port: port, service: "sip" );
	}
}
if(sip_port = get_kb_list( "avm_fritz_box/sip/udp/port" )){
	for port in sip_port {
		concluded = get_kb_item( "avm_fritz_box/sip/udp/" + port + "/concluded" );
		extra += "SIP on port " + port + "/udp\nBanner: " + concluded + "\n";
		register_product( cpe: hw_cpe, location: location, port: port, service: "sip", proto: "udp" );
		register_product( cpe: os_cpe, location: location, port: port, service: "sip", proto: "udp" );
		register_product( cpe: app_cpe, location: location, port: port, service: "sip", proto: "udp" );
	}
}
if(upnp_port = get_kb_list( "avm_fritz_box/upnp/port" )){
	for port in upnp_port {
		concluded = get_kb_item( "avm_fritz_box/upnp/" + port + "/concluded" );
		extra += "UPnP on port " + port + "/udp\nBanner: " + concluded + "\n";
		register_product( cpe: hw_cpe, location: location, port: port, service: "upnp", proto: "udp" );
		register_product( cpe: os_cpe, location: location, port: port, service: "upnp", proto: "udp" );
		register_product( cpe: app_cpe, location: location, port: port, service: "upnp", proto: "udp" );
	}
}
if(ftp_port = get_kb_list( "avm_fritz_box/ftp/port" )){
	for port in ftp_port {
		concluded = get_kb_item( "avm_fritz_box/ftp/" + port + "/concluded" );
		extra += "FTP on port " + port + "/ftp\nBanner: " + concluded + "\n";
		register_product( cpe: hw_cpe, location: location, port: port, service: "ftp" );
		register_product( cpe: os_cpe, location: location, port: port, service: "ftp" );
		register_product( cpe: app_cpe, location: location, port: port, service: "ftp" );
	}
}
report = build_detection_report( app: os_app, version: report_firmware, install: location, cpe: os_cpe );
report += "\n\n" + build_detection_report( app: hw_app, skip_version: TRUE, install: location, cpe: hw_cpe );
if(extra){
	report += "\n\nExposed services:\n";
	report += "\n" + extra;
}
log_message( port: 0, data: report );
exit( 0 );

