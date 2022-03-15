require("plugin_feed_info.inc.sc");
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145661" );
	script_version( "2021-09-28T06:32:28+0000" );
	script_tag( name: "last_modification", value: "2021-09-28 06:32:28 +0000 (Tue, 28 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-03-26 08:32:27 +0000 (Fri, 26 Mar 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "VMware vCenter Server Detection Consolidation" );
	script_tag( name: "summary", value: "Consolidation of VMware vCenter Server detections." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_vmware_vcenter_server_http_detect.sc" );
	if(FEED_NAME == "GSF" || FEED_NAME == "SCM"){
		script_dependencies( "gsf/gb_vmware_vcenter_server_ssh_detect.sc" );
	}
	script_mandatory_keys( "vmware/vcenter/server/detected" );
	script_xref( name: "URL", value: "https://www.vmware.com/products/vcenter-server.html" );
	exit( 0 );
}
if(!get_kb_item( "vmware/vcenter/server/detected" )){
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
detected_version = "unknown";
detected_build = "unknown";
location = "/";
for source in make_list( "http",
	 "ssh" ) {
	version_list = get_kb_list( "vmware/vcenter/server/" + source + "/*/version" );
	for version in version_list {
		if(version != "unknown" && detected_version == "unknown"){
			detected_version = version;
			break;
		}
	}
	build_list = get_kb_list( "vmware/vcenter/server/" + source + "/*/build" );
	for build in build_list {
		if(build != "unknown" && detected_build == "unknown"){
			detected_build = build;
			set_kb_item( name: "vmware/vcenter/server/build", value: detected_build );
			break;
		}
	}
}
cpe1 = build_cpe( value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:vmware:vcenter_server:" );
cpe2 = build_cpe( value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:vmware:vcenter:" );
if(!cpe1){
	cpe1 = "cpe:/a:vmware:vcenter_server";
	cpe2 = "cpe:/a:vmware:vcenter";
}
if(http_ports = get_kb_list( "vmware/vcenter/server/http/port" )){
	for port in http_ports {
		extra += "HTTP(s) on port " + port + "/tcp\n";
		concluded = get_kb_item( "vmware/vcenter/server/http/" + port + "/concluded" );
		concUrl = get_kb_item( "vmware/vcenter/server/http/" + port + "/concludedUrl" );
		if(concluded){
			extra += "  Concluded from version/product identification result: " + concluded + "\n";
		}
		if(concUrl){
			extra += "  Concluded from version/product identification location: " + concUrl + "\n";
		}
		register_product( cpe: cpe1, location: location, port: port, service: "www" );
		register_product( cpe: cpe2, location: location, port: port, service: "www" );
	}
}
if(ssh_ports = get_kb_list( "vmware/vcenter/server/ssh/port" )){
	for port in ssh_ports {
		extra += "SSH on port " + port + "/tcp\n";
		concluded = get_kb_item( "vmware/vcenter/server/ssh/" + port + "/concluded" );
		if(concluded){
			extra += "  Concluded from SSH login banner: " + concluded + "\n";
		}
		register_product( cpe: cpe1, location: location, port: port, service: "ssh" );
		register_product( cpe: cpe2, location: location, port: port, service: "ssh" );
	}
}
report = build_detection_report( app: "VMware vCenter Server", version: detected_version, build: detected_build, install: location, cpe: cpe1 );
if(extra){
	report += "\n\nDetection methods:\n";
	report += "\n" + extra;
}
log_message( port: 0, data: report );
exit( 0 );

