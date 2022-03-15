require("plugin_feed_info.inc.sc");
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143583" );
	script_version( "2021-01-14T13:25:59+0000" );
	script_tag( name: "last_modification", value: "2021-01-14 13:25:59 +0000 (Thu, 14 Jan 2021)" );
	script_tag( name: "creation_date", value: "2020-03-05 08:14:29 +0000 (Thu, 05 Mar 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "IBM Db2 Detection Consolidation" );
	script_tag( name: "summary", value: "Reports the IBM Db2 version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_ibm_db2_ssh_detect.sc", "gb_ibm_db2_das_detect.sc", "gb_ibm_db2_smb_detect.sc" );
	if(FEED_NAME == "GSF" || FEED_NAME == "SCM"){
		script_dependencies( "gsf/gb_ibm_db2_drda_detect.sc" );
	}
	script_mandatory_keys( "ibm/db2/detected" );
	script_xref( name: "URL", value: "https://www.ibm.com/analytics/db2" );
	exit( 0 );
}
if(!get_kb_item( "ibm/db2/detected" )){
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
detected_version = "unknown";
location = "/";
for source in make_list( "ssh-login",
	 "smb",
	 "drda",
	 "das" ) {
	version_list = get_kb_list( "ibm/db2/" + source + "/*/version" );
	for version in version_list {
		if(version != "unknown" && detected_version == "unknown"){
			detected_version = version;
			break;
		}
	}
}
cpe = build_cpe( value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:ibm:db2:" );
if(!cpe){
	cpe = "cpe:/a:ibm:db2";
}
if(ssh_login_ports = get_kb_list( "ibm/db2/ssh-login/port" )){
	for port in ssh_login_ports {
		extra += "SSH login on port " + port + "/tcp\n";
		concluded = get_kb_item( "ibm/db2/ssh-login/" + port + "/concluded" );
		if(concluded){
			extra += "  Concluded: " + concluded + "\n";
		}
		fix_pack = get_kb_item( "ibm/db2/ssh-login/" + port + "/fix_pack" );
		register_product( cpe: cpe, location: location, port: port, service: "ssh-login" );
	}
}
if(drda_ports = get_kb_list( "ibm/db2/drda/port" )){
	for port in drda_ports {
		extra += "DRDA on port " + port + "/tcp\n";
		concluded = get_kb_item( "ibm/db2/drda/" + port + "/concluded" );
		if(concluded){
			extra += "  Concluded from version/product identification result: " + concluded + "\n";
		}
		register_product( cpe: cpe, location: location, port: port, service: "drda" );
	}
}
if(das_ports = get_kb_list( "ibm/db2/das/port" )){
	for port in das_ports {
		extra += "Db2 Administration Server (DAS) on port " + port + "/udp\n";
		concluded = get_kb_item( "ibm/db2/das/" + port + "/concluded" );
		if(concluded){
			extra += "  Concluded from version/product identification result: " + concluded + "\n";
		}
		register_product( cpe: cpe, location: location, port: port, service: "db2-das", proto: "udp" );
	}
}
if(!isnull( concluded = get_kb_item( "ibm/db2/smb/0/concluded" ) )){
	extra += "Local Detection over SMB:\n";
	extra += "  Concluded from:\n" + concluded;
	loc = get_kb_item( "ibm/db2/smb/0/location" );
	if(loc){
		extra += "\nLocation:       " + loc;
	}
	register_product( cpe: cpe, location: loc, port: 0, service: "smb-login" );
}
report = build_detection_report( app: "IBM Db2", version: detected_version, install: location, cpe: cpe, patch: fix_pack );
if(extra){
	report += "\n\nDetection methods:\n\n";
	report += extra;
}
log_message( port: 0, data: report );
exit( 0 );

