require("plugin_feed_info.inc.sc");
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107026" );
	script_version( "2021-02-01T10:40:13+0000" );
	script_tag( name: "last_modification", value: "2021-02-01 10:40:13 +0000 (Mon, 01 Feb 2021)" );
	script_tag( name: "creation_date", value: "2019-06-25 11:28:22 +0200 (Tue, 25 Jun 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "ManageEngine ServiceDesk Plus - MSP Detection Consolidation" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_manageengine_servicedesk_plus_msp_detect.sc" );
	if(FEED_NAME == "GSF" || FEED_NAME == "SCM"){
		script_dependencies( "gsf/gb_manageengine_servicedesk_plus_msp_smb_detect.sc" );
	}
	script_mandatory_keys( "manageengine/servicedesk_plus_msp/detected" );
	script_tag( name: "summary", value: "The script reports a detected ManageEngine ServiceDesk Plus - MSP including the
  version number." );
	script_xref( name: "URL", value: "https://www.manageengine.com/products/service-desk-msp" );
	exit( 0 );
}
CPE = "cpe:/a:zohocorp:manageengine_servicedesk_plus_msp";
require("host_details.inc.sc");
if(!get_kb_item( "manageengine/servicedesk_plus_msp/detected" )){
	exit( 0 );
}
version = "unknown";
build = "unknown";
extra = "";
for proto in make_list( "smb",
	 "http" ) {
	version_list = get_kb_list( "manageengine/servicedesk_plus_msp/" + proto + "/*/version" );
	for ver in version_list {
		if(ver != "unknown" && version == "unknown"){
			version = ver;
		}
	}
	builds_list = get_kb_list( "manageengine/servicedesk_plus_msp/" + proto + "/*/build" );
	for buildnumber in builds_list {
		if(buildnumber != "unknown" && build == "unknown"){
			build = buildnumber;
		}
	}
	if( version != "unknown" && build != "unknown" ){
		CPE += ":" + version + ":b" + build;
		break;
	}
	else {
		if(version != "unknown"){
			CPE += ":" + version;
			break;
		}
	}
}
if(!isnull( concl = get_kb_item( "manageengine/servicedesk_plus_msp/smb/0/concluded" ) )){
	insloc = get_kb_item( "manageengine/servicedesk_plus_msp/smb/0/location" );
	extra += "\n- Local Detection over SMB:\n";
	extra += "\n  Location:      " + insloc;
	extra += "\n  Concluded from:\n" + concl;
	register_product( cpe: CPE, location: insloc, port: 0, service: "smb-login" );
}
if(http_ports = get_kb_list( "manageengine/servicedesk_plus_msp/http/port" )){
	if(extra){
		extra += "\n";
	}
	extra += "\n- Remote Detection over HTTP(s):";
	for port in http_ports {
		concl = get_kb_item( "manageengine/servicedesk_plus_msp/http/" + port + "/concluded" );
		loc = get_kb_item( "manageengine/servicedesk_plus_msp/http/" + port + "/location" );
		extra += "\n";
		extra += "\n  Port:           " + port + "/tcp";
		extra += "\n  Location:       " + loc;
		if(concl){
			extra += "\n  Concluded from:\n" + concl;
		}
		register_product( cpe: CPE, location: loc, port: port, service: "www" );
	}
}
report = build_detection_report( app: "ManageEngine ServiceDesk Plus - MSP", version: version, patch: build, install: "/", cpe: CPE );
if(extra){
	report += "\n\nDetection methods:\n";
	report += extra;
}
log_message( port: 0, data: report );
exit( 0 );

