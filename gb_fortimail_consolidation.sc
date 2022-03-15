require("plugin_feed_info.inc.sc");
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144208" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2020-07-02 07:28:21 +0000 (Thu, 02 Jul 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Fortinet FortiMail Detection Consolidation" );
	script_tag( name: "summary", value: "Consolidation of Fortinet FortiMail detections." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_fortimail_ssh_login_detect.sc" );
	if(FEED_NAME == "GSF" || FEED_NAME == "SCM"){
		script_dependencies( "gsf/gb_fortimail_http_detect.sc" );
	}
	script_mandatory_keys( "fortinet/fortimail/detected" );
	script_xref( name: "URL", value: "https://www.fortinet.com/products/email-security" );
	exit( 0 );
}
if(!get_kb_item( "fortinet/fortimail/detected" )){
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
detected_version = "unknown";
location = "/";
for source in make_list( "ssh-login",
	 "http" ) {
	version_list = get_kb_list( "fortinet/fortimail/" + source + "/*/version" );
	for version in version_list {
		if(version != "unknown" && detected_version == "unknown"){
			detected_version = version;
			break;
		}
	}
}
os_register_and_report( os: "Fortinet FortiOS", cpe: "cpe:/o:fortinet:fortios", desc: "Fortinet FortiMail Detection Consolidation", runs_key: "unixoide" );
cpe = build_cpe( value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:fortinet:fortimail:" );
if(!cpe){
	cpe = "cpe:/a:fortinet:fortimail";
}
if(ssh_login_ports = get_kb_list( "fortinet/fortimail/ssh-login/port" )){
	extra += "Local Detection over SSH:\n";
	for port in ssh_login_ports {
		concluded = get_kb_item( "fortinet/fortimail/ssh-login/" + port + "/concluded" );
		extra += "  Port:                           " + port + "/tcp\n";
		if(concluded){
			extra += "  Concluded from version/product\n";
		}
		extra += "  identification result:          " + concluded;
		register_product( cpe: cpe, location: location, port: port, service: "ssh-login" );
	}
}
if(http_ports = get_kb_list( "fortinet/fortimail/http/port" )){
	if(extra){
		extra += "\n\n";
	}
	extra += "Remote Detection over HTTP(s):\n";
	for port in http_ports {
		extra += "  Port:   " + port + "/tcp\n";
		register_product( cpe: cpe, location: location, port: port, service: "www" );
	}
}
report = build_detection_report( app: "Fortinet FortiMail", version: detected_version, cpe: cpe, install: "/" );
if(extra){
	report += "\n\nDetection methods:\n";
	report += extra;
}
log_message( port: 0, data: report );
exit( 0 );

