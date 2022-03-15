if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144564" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2020-09-11 07:35:31 +0000 (Fri, 11 Sep 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Cisco UCS Director Detection Consolidation" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_ucs_director_ssh_login_detect.sc", "gb_cisco_ucs_director_http_detect.sc" );
	script_mandatory_keys( "cisco/ucs_director/detected" );
	script_tag( name: "summary", value: "Consolidation of Cisco UCS Director detections." );
	script_xref( name: "URL", value: "https://www.cisco.com/c/en/us/products/servers-unified-computing/ucs-director/index.html" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!get_kb_item( "cisco/ucs_director/detected" )){
	exit( 0 );
}
detected_version = "unknown";
detected_build = "unknown";
location = "/";
for source in make_list( "ssh-login",
	 "http" ) {
	version_list = get_kb_list( "cisco/ucs_director/" + source + "/*/version" );
	for version in version_list {
		if(version != "unknown" && detected_version == "unknown"){
			detected_version = version;
			break;
		}
	}
	build_list = get_kb_list( "cisco/ucs_director/" + source + "/*/build" );
	for build in build_list {
		if(build != "unknown" && detected_build == "unknown"){
			detected_build = build;
			set_kb_item( name: "cisco/ucs_director/build", value: detected_build );
			break;
		}
	}
}
cpe = build_cpe( value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:cisco:ucs_director:" );
if(!cpe){
	cpe = "cpe:/a:cisco:ucs_director";
}
os_register_and_report( os: "CentOS", cpe: "cpe:/o:centos:centos", desc: "Cisco UCS Director Detection Consolidation", runs_key: "unixoide" );
if(http_ports = get_kb_list( "cisco/ucs_director/http/port" )){
	for port in http_ports {
		extra += "HTTP(s) on port " + port + "/tcp\n";
		concUrl = get_kb_item( "cisco/ucs_director/http/" + port + "/concludedUrl" );
		if(concUrl){
			extra += "  Concluded from version/product identification location: " + concUrl + "\n";
		}
		register_product( cpe: cpe, location: location, port: port, service: "www" );
	}
}
if(sshlogin_ports = get_kb_list( "cisco/ucs_director/ssh-login/port" )){
	for port in sshlogin_ports {
		extra += "SSH login on port " + port + "/tcp\n";
		concluded = get_kb_item( "cisco/ucs_director/ssh-login/" + port + "/concluded" );
		if(concluded){
			extra += "  Concluded from version/product identification result: " + concluded;
		}
		register_product( cpe: cpe, location: location, port: port, service: "ssh-login" );
	}
}
report = build_detection_report( app: "Cisco UCS Director", version: detected_version, install: location, cpe: cpe, extra: "Build: " + detected_build );
if(extra){
	report += "\n\nDetection methods:\n";
	report += "\n" + extra;
}
log_message( port: 0, data: report );
exit( 0 );
