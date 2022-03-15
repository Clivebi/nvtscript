if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141717" );
	script_version( "2020-01-07T12:31:05+0000" );
	script_tag( name: "last_modification", value: "2020-01-07 12:31:05 +0000 (Tue, 07 Jan 2020)" );
	script_tag( name: "creation_date", value: "2018-11-28 11:36:08 +0700 (Wed, 28 Nov 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "IBM MQ Detection Consolidation" );
	script_tag( name: "summary", value: "The script reports a detected IBM MQ including the version number." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_ibm_websphere_mq_detect.sc", "gb_ibm_websphere_mq_detect_lin.sc", "gb_ibm_websphere_mq_mqi_detect.sc" );
	script_mandatory_keys( "ibm_websphere_mq/detected" );
	script_xref( name: "URL", value: "https://www.ibm.com/products/mq" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
if(!get_kb_item( "ibm_websphere_mq/detected" )){
	exit( 0 );
}
detected_version = "unknown";
for source in make_list( "win",
	 "lin",
	 "mqi" ) {
	version_list = get_kb_list( "ibm_websphere_mq/" + source + "/*/version" );
	for vers in version_list {
		if(vers != "unknown" && detected_version == "unknown"){
			detected_version = vers;
		}
	}
}
cpe = build_cpe( value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:ibm:mq:" );
if(!cpe){
	cpe = "cpe:/a:ibm:mq";
}
cpe2 = build_cpe( value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:ibm:websphere_mq:" );
if(!cpe2){
	cpe2 = "cpe:/a:ibm:websphere_mq";
}
if(mqi_ports = get_kb_list( "ibm_websphere_mq/mqi/port" )){
	if(!isnull( mqi_ports )){
		extra += "\nRemote Detection over MQI:\n";
	}
	for port in mqi_ports {
		extra += "   Port:  " + port + "\n";
		register_product( cpe: cpe, location: port + "/tcp", port: port, service: "websphere_mqi" );
		register_product( cpe: cpe2, location: port + "/tcp", port: port, service: "websphere_mqi" );
	}
}
if( bin_path = get_kb_item( "ibm_websphere_mq/lin/local/path" ) ){
	extra += "Local Detection on Linux:\n";
	extra += "   Path:  " + bin_path + "\n";
	register_product( cpe: cpe, location: bin_path, port: 0, service: "ssh-login" );
	register_product( cpe: cpe2, location: bin_path, port: 0, service: "ssh-login" );
}
else {
	if( x86_path = get_kb_item( "ibm_websphere_mq/win/x86/path" ) ){
		extra += "Local Detection on Windows (x86):\n";
		extra += "   Path:  " + x86_path + "\n";
		register_product( cpe: cpe, location: x86_path, port: 0, service: "smb-login" );
		register_product( cpe: cpe2, location: x86_path, port: 0, service: "smb-login" );
	}
	else {
		if(x64_path = get_kb_item( "ibm_websphere_mq/win/x64/path" )){
			extra += "Local Detection on Windows (x64):\n";
			extra += "   Path:  " + x64_path + "\n";
			cpe = build_cpe( value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:ibm:mq:x64:" );
			if(!cpe){
				cpe = "cpe:/a:ibm:mq:x64";
			}
			cpe2 = build_cpe( value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:ibm:websphere_mq:x64:" );
			if(!cpe2){
				cpe2 = "cpe:/a:ibm:websphere_mq:x64";
			}
			register_product( cpe: cpe, location: x64_path, port: 0, service: "smb-login" );
			register_product( cpe: cpe2, location: x64_path, port: 0, service: "smb-login" );
		}
	}
}
report = build_detection_report( app: "IBM MQ", version: detected_version, cpe: cpe, extra: extra );
if(report){
	log_message( port: 0, data: report );
}
exit( 0 );

