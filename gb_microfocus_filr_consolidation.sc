if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145045" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2020-12-15 09:41:04 +0000 (Tue, 15 Dec 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Micro Focus (Novell) Filr Detection Consolidation" );
	script_tag( name: "summary", value: "Consolidation of Micro Focus (Novell) Filr detections." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_microfocus_filr_ssh_login_detect.sc" );
	script_mandatory_keys( "microfocus/filr/detected" );
	script_xref( name: "URL", value: "https://www.microfocus.com/en-us/products/filr/overview" );
	exit( 0 );
}
if(!get_kb_item( "microfocus/filr/detected" )){
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
detected_version = "unknown";
location = "/";
for source in make_list( "ssh-login",
	 "http",
	 "admin_http" ) {
	version_list = get_kb_list( "microfocus/filr/" + source + "/*/version" );
	for version in version_list {
		if(version != "unknown" && detected_version == "unknown"){
			detected_version = version;
			break;
		}
	}
}
cpe = build_cpe( value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:microfocus:filr:" );
if(!cpe){
	cpe = "cpe:/a:microfocus:filr";
}
os_register_and_report( os: "Linux", cpe: "cpe:/o:linux:kernel", desc: "Micro Focus (Novell) Filr Detection Consolidation", runs_key: "unixoide" );
if(http_ports = get_kb_list( "microfocus/filr/http/port" )){
	for port in http_ports {
		extra += "HTTP(s) on port " + port + "/tcp\n";
		concluded = get_kb_item( "microfocus/filr/http/" + port + "/concluded" );
		concUrl = get_kb_item( "microfocus/filr/http/" + port + "/concludedUrl" );
		if(concluded){
			extra += "  Concluded from version/product identification result: " + concluded + "\n";
			extra += "  Concluded from version/product identification location: " + concUrl + "\n";
		}
		register_product( cpe: cpe, location: location, port: port, service: "www" );
	}
}
if(admin_http_ports = get_kb_list( "microfocus/filr/admin_http/port" )){
	for port in admin_http_ports {
		extra += "Admin UI over HTTP(s) on port " + port + "/tcp\n";
		register_product( cpe: cpe, location: location, port: port, service: "www" );
	}
}
if(ssh_login_ports = get_kb_list( "microfocus/filr/ssh-login/port" )){
	for port in ssh_login_ports {
		extra += "SSH login on port " + port + "/tcp\n";
		concluded = get_kb_item( "microfocus/filr/ssh-login/" + port + "/concluded" );
		if(concluded){
			extra += "  Concluded from version/product identification result:\n" + concluded + "\n";
		}
		register_product( cpe: cpe, location: location, port: port, service: "ssh-login" );
	}
}
report = build_detection_report( app: "Micro Focus (Novell) Filr", version: detected_version, install: location, cpe: cpe );
if(extra){
	report += "\n\nDetection methods:\n";
	report += "\n" + extra;
}
log_message( port: 0, data: report );
exit( 0 );

