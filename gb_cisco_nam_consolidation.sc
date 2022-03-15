require("plugin_feed_info.inc.sc");
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144170" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2020-06-25 09:49:44 +0000 (Thu, 25 Jun 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Cisco Network Analysis Module Detection Consolidation" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_cisco_nam_ssh_login.sc", "gb_cisco_nam_http_detect.sc" );
	if(FEED_NAME == "GSF" || FEED_NAME == "SCM"){
		script_dependencies( "gsf/gb_cisco_nam_snmp_detect.sc" );
	}
	script_mandatory_keys( "cisco/nam/detected" );
	script_tag( name: "summary", value: "Consolidation of Cisco Network Analysis Module detections." );
	script_xref( name: "URL", value: "https://www.cisco.com/c/en/us/products/cloud-systems-management/network-analysis-module-nam/index.html" );
	exit( 0 );
}
if(!get_kb_item( "cisco/nam/detected" )){
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
detected_version = "unknown";
detected_patch = "No patch installed/detected";
location = "/";
for source in make_list( "ssh-login",
	 "http",
	 "snmp" ) {
	version_list = get_kb_list( "cisco/nam/" + source + "/*/version" );
	for version in version_list {
		if(version != "unknown" && detected_version == "unknown"){
			detected_version = version;
			break;
		}
	}
	patch_list = get_kb_list( "cisco/nam/" + source + "/*/patch" );
	for patch in patch_list {
		if(patch != "unknown" && detected_patch == "No patch installed/detected"){
			detected_patch = patch;
			set_kb_item( name: "cisco/nam/patch", value: detected_patch );
			break;
		}
	}
}
cpe = build_cpe( value: tolower( version ), exp: "([0-9a-z.]+)", base: "cpe:/a:cisco:prime_network_analysis_module:" );
if(!cpe){
	cpe = "cpe:/a:cisco:prime_network_analysis_module";
}
os_register_and_report( os: "Cisco NAM", cpe: "cpe:/o:cisco:prime_network_analysis_module_firmware", desc: "Cisco Network Analysis Module Detection Consolidation", runs_key: "unixoide" );
if(ssh_login_ports = get_kb_list( "cisco/nam/ssh-login/port" )){
	extra += "Local Detection over SSH:\n";
	for port in ssh_login_ports {
		concluded = get_kb_item( "cisco/nam/ssh-login/" + port + "/concluded" );
		extra += "  Port:                           " + port + "/tcp\n";
		if(concluded){
			extra += "  Concluded from version/product\n";
		}
		extra += "  identification result:          " + concluded;
		register_product( cpe: cpe, location: location, port: port, service: "ssh-login" );
	}
}
if(http_ports = get_kb_list( "cisco/nam/http/port" )){
	if(extra){
		extra += "\n\n";
	}
	extra += "Remote Detection over HTTP(s):\n";
	for port in http_ports {
		concluded = get_kb_item( "cisco/nam/http/" + port + "/concluded" );
		extra += "  Port:                           " + port + "/tcp\n";
		if(concluded){
			extra += "  Concluded from:                 " + concluded + "\n";
		}
		register_product( cpe: cpe, location: location, port: port, service: "www" );
	}
}
if(snmp_ports = get_kb_list( "cisco/nam/snmp/port" )){
	if(extra){
		extra += "\n\n";
	}
	extra += "Remote Detection over SNMP:\n";
	for port in snmp_ports {
		concluded = get_kb_item( "cisco/nam/snmp/" + port + "/concluded" );
		extra += "Port                              " + port + "/udp\n";
		if(concluded){
			extra += "  SNMP Banner:                    " + concluded + "\n";
		}
		register_product( cpe: cpe, location: location, port: port, service: "snmp", proto: "udp" );
	}
}
report = build_detection_report( app: "Cisco Network Analysis Module", version: detected_version, cpe: cpe, install: location, patch: detected_patch );
if(extra){
	report += "\n\nDetection methods:\n";
	report += "\n" + extra;
}
log_message( port: 0, data: report );
exit( 0 );

