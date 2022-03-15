if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108488" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2018-11-28 14:02:54 +0100 (Wed, 28 Nov 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Western Digital My Cloud / WD Cloud Products Detection Consolidation" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "gb_wd_mycloud_snmp_detect.sc", "gb_wd_mycloud_ssh_login_detect.sc", "gb_wd_mycloud_http_detect.sc" );
	script_mandatory_keys( "wd-mycloud/detected" );
	script_xref( name: "URL", value: "https://support.wdc.com/cat_products.aspx?ID=1" );
	script_tag( name: "summary", value: "The script reports a detected Western Digital My Cloud product (Called 'WD Cloud' in Japan)
  including the version number and exposed services." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!get_kb_item( "wd-mycloud/detected" )){
	exit( 0 );
}
detected_version = "unknown";
detected_model = "unknown";
for source in make_list( "ssh-login",
	 "snmp",
	 "http" ) {
	version_list = get_kb_list( "wd-mycloud/" + source + "/*/version" );
	for version in version_list {
		if(version != "unknown" && detected_version == "unknown"){
			detected_version = version;
			set_kb_item( name: "wd-mycloud/version", value: version );
			break;
		}
	}
	model_list = get_kb_list( "wd-mycloud/" + source + "/*/model" );
	for model in model_list {
		if(model != "unknown" && detected_model == "unknown"){
			detected_model = model;
			set_kb_item( name: "wd-mycloud/model", value: model );
			break;
		}
	}
}
if( detected_model != "unknown" ){
	if( model == "base" ){
		os_app = "Western Digital My Cloud Firmware";
		os_cpe = "cpe:/o:wdc:my_cloud_firmware";
		hw_app = "Western Digital My Cloud Device";
		hw_cpe = "cpe:/h:wdc:my_cloud";
	}
	else {
		if( model == "WD Cloud" ){
			os_app = "Western Digital WD Cloud Firmware";
			os_cpe = "cpe:/o:wdc:wd_cloud_firmware";
			hw_app = "Western Digital WD Cloud Device";
			hw_cpe = "cpe:/h:wdc:wd_cloud";
		}
		else {
			os_app = "Western Digital My Cloud " + detected_model + " Firmware";
			os_cpe = "cpe:/o:wdc:my_cloud_" + tolower( detected_model ) + "_firmware";
			hw_app = "Western Digital My Cloud " + detected_model + " Device";
			hw_cpe = "cpe:/h:wdc:my_cloud_" + tolower( detected_model );
		}
	}
}
else {
	os_app = "Western Digital My Cloud / WD Cloud Unknown Model Firmware";
	os_cpe = "cpe:/o:wdc:my_cloud_unknown_model_firmware";
	hw_app = "Western Digital My Cloud / WD Cloud Unknown Model Device";
	hw_cpe = "cpe:/h:wdc:my_cloud_unknown_model";
}
if(detected_version != "unknown"){
	os_cpe += ":" + detected_version;
}
os_register_and_report( os: os_app, cpe: os_cpe, desc: "Western Digital My Cloud / WD Cloud Products Detection Consolidation", runs_key: "unixoide" );
set_kb_item( name: "wd/product/detected", value: TRUE );
location = "/";
if(ssh_login_ports = get_kb_list( "wd-mycloud/ssh-login/port" )){
	for port in ssh_login_ports {
		detection_methods += "\nSSH login on port " + port + "/tcp\n";
		concluded = get_kb_item( "wd-mycloud/ssh-login/" + port + "/concluded" );
		if(concluded){
			detection_methods += "Concluded: " + concluded + "\n";
		}
		register_product( cpe: hw_cpe, location: location, port: port, service: "ssh-login" );
		register_product( cpe: os_cpe, location: location, port: port, service: "ssh-login" );
	}
}
if(http_ports = get_kb_list( "wd-mycloud/http/port" )){
	for port in http_ports {
		detection_methods += "\nHTTP(s) on port " + port + "/tcp\n";
		concluded = get_kb_item( "wd-mycloud/http/" + port + "/concluded" );
		concludedUrl = get_kb_item( "wd-mycloud/http/" + port + "/concludedUrl" );
		if( concluded && concludedUrl ) {
			detection_methods += "Concluded: " + concluded + "\nfrom URL(s): " + concludedUrl + "\n";
		}
		else {
			if(concluded){
				detection_methods += "Concluded: " + concluded + "\n";
			}
		}
		extra = get_kb_item( "wd-mycloud/http/" + port + "/extra" );
		extraUrl = get_kb_item( "wd-mycloud/http/" + port + "/extraUrl" );
		if(extra && extraUrl){
			extra_info += extraUrl + ": " + extra + "\n";
		}
		register_product( cpe: hw_cpe, location: location, port: port, service: "www" );
		register_product( cpe: os_cpe, location: location, port: port, service: "www" );
	}
}
if(snmp_ports = get_kb_list( "wd-mycloud/snmp/port" )){
	for port in snmp_ports {
		detection_methods += "\nSNMP on port " + port + "/udp\n";
		concludedVers = get_kb_item( "wd-mycloud/snmp/" + port + "/concludedVers" );
		concludedVersOID = get_kb_item( "wd-mycloud/snmp/" + port + "/concludedVersOID" );
		if(concludedVers && concludedVersOID){
			detection_methods += "Concluded from: \"" + concludedVers + "\" via OID: \"" + concludedVersOID + "\"\n";
		}
		concludedMod = get_kb_item( "wd-mycloud/snmp/" + port + "/concludedMod" );
		concludedModOID = get_kb_item( "wd-mycloud/snmp/" + port + "/concludedModOID" );
		if(concludedMod && concludedModOID){
			detection_methods += "Concluded from: \"" + concludedMod + "\" via OID: \"" + concludedModOID + "\"\n";
		}
		register_product( cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp" );
		register_product( cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp" );
	}
}
report = build_detection_report( app: os_app, version: detected_version, install: location, cpe: os_cpe );
report += "\n\n";
report += build_detection_report( app: hw_app, skip_version: TRUE, install: location, cpe: hw_cpe );
if(detection_methods){
	report += "\n\nDetection methods:\n" + detection_methods;
}
report = chomp( report );
if(extra_info){
	report += "\n\nExtra info collected (URL:Info):\n" + extra_info;
}
log_message( port: 0, data: chomp( report ) );
exit( 0 );

