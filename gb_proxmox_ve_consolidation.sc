require("plugin_feed_info.inc.sc");
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117270" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-03-24 12:47:40 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Proxmox Virtual Environment (VE, PVE) Detection Consolidation" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_dependencies( "sw_proxmox_ve_http_detect.sc" );
	if(FEED_NAME == "GSF" || FEED_NAME == "SCM"){
		script_dependencies( "gsf/gb_proxmox_ve_ssh_login_detect.sc", "gsf/gb_proxmox_ve_snmp_detect.sc" );
	}
	script_mandatory_keys( "proxmox/ve/detected" );
	script_tag( name: "summary", value: "Consolidation of Proxmox Virtual Environment (VE, PVE) detections." );
	script_xref( name: "URL", value: "https://pve.proxmox.com" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!get_kb_item( "proxmox/ve/detected" )){
	exit( 0 );
}
detected_version = "unknown";
location = "/";
extra = "\nDetection methods:\n";
proxmox_ve_debian_mapping = make_array( "6", "10", "5", "9", "4", "8", "3", "7", "2", "6", "1", "5" );
for source in make_list( "ssh-login",
	 "snmp",
	 "http" ) {
	version_list = get_kb_list( "proxmox/ve/" + source + "/*/version" );
	for version in version_list {
		if(version && detected_version == "unknown"){
			detected_version = version;
			break;
		}
	}
}
if( detected_version != "unknown" ){
	cpe = "cpe:/a:proxmox:virtual_environment:" + detected_version;
	major = eregmatch( string: detected_version, pattern: "^([0-9]+)\\.", icase: FALSE );
	if(major[1]){
		if( proxmox_ve_debian_mapping[major[1]] ) {
			deb_os_version = proxmox_ve_debian_mapping[major[1]];
		}
		else {
			deb_os_version = "";
		}
	}
}
else {
	cpe = "cpe:/a:proxmox:virtual_environment";
	deb_os_version = "";
}
os_register_and_report( os: "Debian GNU/Linux", cpe: "cpe:/o:debian:debian_linux", version: deb_os_version, banner_type: "Debian version fingerprinting based on the Proxmox VE major version", desc: "Proxmox Virtual Environment (VE, PVE) Detection Consolidation", runs_key: "unixoide" );
if(http_port = get_kb_list( "proxmox/ve/http/port" )){
	for port in http_port {
		concluded = get_kb_item( "proxmox/ve/http/" + port + "/concluded" );
		concludedUrl = get_kb_item( "proxmox/ve/http/" + port + "/concludedUrl" );
		extra += "\n- HTTP(s) on port " + port + "/tcp";
		if(concluded){
			extra += "\n  Concluded from version/product identification result:\n" + concluded + "\n";
		}
		if(concludedUrl){
			extra += "\n  Concluded from version/product identification location:\n" + concludedUrl + "\n";
		}
		register_product( cpe: cpe, location: location, port: port, service: "www" );
	}
}
if(ssh_port = get_kb_list( "proxmox/ve/ssh-login/port" )){
	for port in ssh_port {
		concluded = get_kb_item( "proxmox/ve/ssh-login/" + port + "/concluded" );
		extra += "\n- SSH login on port " + port + "/tcp";
		if(concluded){
			extra += "\n  Concluded from version/product identification result (dpkg -l):\n" + concluded + "\n";
		}
		register_product( cpe: cpe, location: location, port: 0, service: "ssh-login" );
	}
}
if(snmp_port = get_kb_list( "proxmox/ve/snmp/port" )){
	for port in snmp_port {
		concluded = get_kb_item( "proxmox/ve/snmp/" + port + "/concluded" );
		concludedOID = get_kb_item( "proxmox/ve/snmp/" + port + "/concludedOID" );
		extra += "\n- SNMP on port " + port + "/udp";
		if(concluded){
			extra += "\n  Concluded from version/product identification result:\n" + concluded + "\n";
		}
		if(concludedOID){
			extra += "\n  Concluded from version/product identification location (OID):\n" + concludedOID + "\n";
		}
		register_product( cpe: cpe, location: location, port: port, service: "snmp", proto: "udp" );
	}
}
report = build_detection_report( app: "Proxmox Virtual Environment (VE, PVE)", version: detected_version, install: location, cpe: cpe );
report += "\n" + extra;
log_message( port: 0, data: chomp( report ) );
exit( 0 );

