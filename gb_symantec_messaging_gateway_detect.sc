if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103612" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "$Revision: 11499 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-20 12:38:00 +0200 (Thu, 20 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2016-05-17 13:22:07 +0200 (Tue, 17 May 2016)" );
	script_name( "Symantec Messaging Gateway Version Detection" );
	script_tag( name: "summary", value: "This Script reports the detected Symantec Messaging Gateway Version" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_symantec_messaging_gateway_http_detect.sc", "gb_symantec_messaging_gateway_ssh_detect.sc", "gb_symantec_messaging_gateway_snmp_detect.sc" );
	script_mandatory_keys( "symantec_smg/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
if(!get_kb_item( "symantec_smg/detected" )){
	exit( 0 );
}
detected_version = "unknown";
version = get_kb_item( "symantec_smg/ssh/version" );
if(version){
	detected_version = version;
	ssh_detected = TRUE;
}
if(detected_version == "unknown"){
	for source in make_list( "snmp",
		 "http" ) {
		version_list = get_kb_list( "symantec_smg/" + source + "/*/version" );
		for version in version_list {
			if(version && detected_version == "unknown"){
				detected_version = version;
			}
		}
	}
}
if( detected_version != "unknown" ) {
	cpe = "cpe:/a:symantec:messaging_gateway:" + detected_version;
}
else {
	cpe = "cpe:/a:symantec:messaging_gateway";
}
if(ssh_detected){
	extra += "Authenticated over SSH.\n";
	patch = get_kb_item( "symantec_smg/ssh/patch" );
	if(patch){
		patch_detected = TRUE;
		set_kb_item( name: "symantec_smg/patch", value: patch );
		detected_patch = patch;
	}
	register_product( cpe: cpe, location: "/", port: 0 );
}
if(snmp_ports = get_kb_list( "symantec_smg/snmp/port" )){
	for port in snmp_ports {
		extra += "SNMP on port " + port + "/udp\n";
		patch = get_kb_item( "symantec_smg/snmp/" + port + "/patch" );
		if(patch){
			if(!patch_detected){
				patch_detected = TRUE;
				set_kb_item( name: "symantec_smg/patch", value: patch );
				detected_patch = patch;
			}
		}
		register_product( cpe: cpe, location: port + "/udp", port: port, service: "snmp", proto: "udp" );
	}
}
if(http_ports = get_kb_list( "symantec_smg/http/port" )){
	for port in http_ports {
		extra += "HTTP on port " + port + "/tcp\n";
		concluded = get_kb_item( "symantec_smg/http/" + port + "/concluded" );
		if(concluded){
			extra += "Concluded from:  " + concluded + "\n";
		}
		register_product( cpe: cpe, location: port + "/", port: port, service: "www" );
	}
}
report = build_detection_report( app: "Symantec Messaging Gateway", version: detected_version, install: "/", cpe: cpe );
if(detected_patch){
	report += "\nPatch:    " + detected_patch;
}
if(extra){
	report += "\n\nDetection methods:\n";
	report += "\n" + extra;
}
log_message( port: 0, data: report );
exit( 0 );

