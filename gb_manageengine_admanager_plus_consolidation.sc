if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146787" );
	script_version( "2021-09-28T13:54:13+0000" );
	script_tag( name: "last_modification", value: "2021-09-28 13:54:13 +0000 (Tue, 28 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-27 12:09:54 +0000 (Mon, 27 Sep 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "ManageEngine ADManager Plus Detection Consolidation" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_manageengine_admanager_plus_smb_login_detect.sc", "gb_manageengine_admanager_plus_http_detect.sc" );
	script_mandatory_keys( "manageengine/admanager_plus/detected" );
	script_tag( name: "summary", value: "Consolidation of ManageEngine ADManager Plus detections." );
	script_xref( name: "URL", value: "https://www.manageengine.com/products/ad-manager/" );
	exit( 0 );
}
if(!get_kb_item( "manageengine/admanager_plus/detected" )){
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
detected_version = "unknown";
detected_build = "unknown";
location = "/";
for source in make_list( "smb-login",
	 "http" ) {
	version_list = get_kb_list( "manageengine/admanager_plus/" + source + "/*/version" );
	for version in version_list {
		if(version != "unknown" && detected_version == "unknown"){
			detected_version = version;
			break;
		}
	}
	build_list = get_kb_list( "manageengine/admanager_plus/" + source + "/*/build" );
	for build in build_list {
		if(build != "unknown" && detected_build == "unknown"){
			detected_build = build;
			break;
		}
	}
}
cpe = build_cpe( value: detected_version + ":" + detected_build, exp: "^([0-9.]+):([0-9]+)?", base: "cpe:/a:zohocorp:manageengine_admanager_plus:" );
if(!cpe){
	cpe = "cpe:/a:zohocorp:manageengine_admanager_plus";
}
os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", desc: "ManageEngine ADManager Plus Detection Consolidation", runs_key: "windows" );
if(!isnull( concluded = get_kb_item( "manageengine/admanager_plus/smb-login/0/concluded" ) )){
	loc = get_kb_item( "manageengine/admanager_plus/smb-login/0/location" );
	extra = "\n- Local Detection via SMB login\n\n" + concluded + "\n";
	extra += "  Location:       " + loc + "\n";
	register_product( cpe: cpe, location: loc, port: 0, service: "smb-login" );
}
if(http_ports = get_kb_list( "manageengine/admanager_plus/http/port" )){
	if(extra){
		extra += "\n";
	}
	extra += "\n- Remote Detection over HTTP(s)" + "\n\n";
	for port in http_ports {
		concluded = get_kb_item( "manageengine/admanager_plus/http/" + port + "/concluded" );
		extra += "  Port:           " + port + "/tcp\n";
		if(concluded){
			extra += "  Concluded from: " + concluded + "\n";
		}
		register_product( cpe: cpe, location: location, port: port, service: "www" );
	}
}
report = build_detection_report( app: "ManageEngine ADManager Plus", version: detected_version, build: detected_build, install: location, cpe: cpe );
if(extra){
	report += "\n\nDetection methods:\n";
	report += extra;
}
log_message( port: 0, data: chomp( report ) );
exit( 0 );

