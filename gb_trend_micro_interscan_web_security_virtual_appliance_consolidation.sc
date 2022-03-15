if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144152" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2020-06-22 07:53:05 +0000 (Mon, 22 Jun 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Trend Micro Interscan Web Security Virtual Appliance Detection Consolidation" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_trend_micro_interscan_web_security_virtual_appliance_ssh_login_detect.sc", "gb_trend_micro_interscan_web_security_virtual_appliance_http_detect.sc" );
	script_mandatory_keys( "trendmicro/IWSVA/detected" );
	script_tag( name: "summary", value: "Consolidation of Trend Micro Interscan Web Security Virtual Appliance detections." );
	script_xref( name: "URL", value: "https://success.trendmicro.com/product-support/interscan-web-security-virtual-appliance/" );
	exit( 0 );
}
if(!get_kb_item( "trendmicro/IWSVA/detected" )){
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
detected_version = "unknown";
detected_build = "unknown";
location = "/";
for source in make_list( "ssh-login",
	 "http" ) {
	version_list = get_kb_list( "trendmicro/IWSVA/" + source + "/*/version" );
	for version in version_list {
		if(version != "unknown" && detected_version == "unknown"){
			detected_version = version;
			break;
		}
	}
	build_list = get_kb_list( "trendmicro/IWSVA/" + source + "/*/build" );
	for build in build_list {
		if(build != "unknown" && detected_build == "unknown"){
			detected_build = build;
			set_kb_item( name: "trendmicro/IWSVA/build", value: detected_build );
			break;
		}
	}
}
cpe = build_cpe( value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:trendmicro:interscan_web_security_virtual_appliance:" );
if(!cpe){
	cpe = "cpe:/a:trendmicro:interscan_web_security_virtual_appliance";
}
os_register_and_report( os: "Linux", cpe: "cpe:/o:linux:kernel", desc: "Trend Micro Interscan Web Security Virtual Appliance Detection Consolidation", runs_key: "unixoide" );
if(ssh_login_ports = get_kb_list( "trendmicro/IWSVA/ssh-login/port" )){
	extra += "Local Detection over SSH:\n";
	for port in ssh_login_ports {
		concluded = get_kb_item( "trendmicro/IWSVA/ssh-login/" + port + "/concluded" );
		extra += "  Port:                           " + port + "/tcp\n";
		if(concluded){
			extra += "  Concluded from version/product\n";
		}
		extra += "  identification result:          " + concluded;
		register_product( cpe: cpe, location: location, port: port, service: "ssh-login" );
	}
}
if(http_ports = get_kb_list( "trendmicro/IWSVA/http/port" )){
	if(extra){
		extra += "\n\n";
	}
	extra += "Remote Detection over HTTP(s):\n";
	for port in http_ports {
		concluded = get_kb_item( "trendmicro/IWSVA/http/" + port + "/concluded" );
		concUrl = get_kb_item( "trendmicro/IWSVA/http/" + port + "/concludedUrl" );
		extra += "  Port:                           " + port + "/tcp\n";
		if(concluded){
			extra += "  Concluded from:                 " + concluded + "\n";
			extra += "  Concluded from version/product\n  identification location:        " + concUrl;
		}
		register_product( cpe: cpe, location: location, port: port, service: "www" );
	}
}
report = build_detection_report( app: "Trend Micro Interscan Web Security Virtual Appliance", version: detected_version, cpe: cpe, install: location, extra: "Build: " + detected_build );
if(extra){
	report += "\n\nDetection methods:\n";
	report += "\n" + extra;
}
log_message( port: 0, data: report );
exit( 0 );

