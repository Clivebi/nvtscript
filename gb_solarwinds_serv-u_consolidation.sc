require("plugin_feed_info.inc.sc");
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142490" );
	script_version( "2019-06-24T10:26:25+0000" );
	script_tag( name: "last_modification", value: "2019-06-24 10:26:25 +0000 (Mon, 24 Jun 2019)" );
	script_tag( name: "creation_date", value: "2019-06-05 02:35:07 +0000 (Wed, 05 Jun 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "SolarWinds Serv-U Consolidation" );
	script_tag( name: "summary", value: "The script reports a detected SolarWinds Serv-U including the version number." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_rhinosoft_serv-u_detect.sc" );
	if(FEED_NAME == "GSF" || FEED_NAME == "SCM"){
		script_dependencies( "gsf/gb_solarwinds_serv-u_ssh_detect.sc", "gsf/gb_solarwinds_serv-u_http_detect.sc" );
	}
	script_mandatory_keys( "solarwinds/servu/detected" );
	script_xref( name: "URL", value: "https://www.serv-u.com/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
if(!get_kb_item( "solarwinds/servu/detected" )){
	exit( 0 );
}
detected_version = "unknown";
for source in make_list( "http",
	 "ssh",
	 "ftp" ) {
	version_list = get_kb_list( "solarwinds/servu/" + source + "/*/version" );
	for vers in version_list {
		if(vers != "unknown" && detected_version == "unknown"){
			detected_version = vers;
		}
	}
}
cpe = build_cpe( value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:serv-u:serv-u:" );
if(!cpe){
	cpe = "cpe:/a:serv-u:serv-u";
}
if(http_ports = get_kb_list( "solarwinds/servu/http/port" )){
	extra += "\nRemote Detection over HTTP(S):\n";
	for port in http_ports {
		concluded = get_kb_item( "solarwinds/servu/http/" + port + "/concluded" );
		extra += "   Port:       " + port + "/tcp\n";
		if(concluded){
			extra += "   Concluded:  " + concluded + "\n";
		}
		register_product( cpe: cpe, location: "/", port: port, service: "www" );
	}
}
if(ssh_ports = get_kb_list( "solarwinds/servu/ssh/port" )){
	extra += "\nRemote Detection over SSH:\n";
	for port in ssh_ports {
		concluded = get_kb_item( "solarwinds/servu/ssh/" + port + "/concluded" );
		extra += "   Port:       " + port + "/tcp\n";
		if(concluded){
			extra += "   Concluded:  " + concluded + "\n";
		}
		register_product( cpe: cpe, location: "/", port: port, service: "ssh" );
	}
}
if(ftp_ports = get_kb_list( "solarwinds/servu/ftp/port" )){
	extra += "\nRemote Detection over FTP:\n";
	for port in ftp_ports {
		concluded = get_kb_item( "solarwinds/servu/ftp/" + port + "/concluded" );
		extra += "   Port:       " + port + "/tcp\n";
		if(concluded){
			extra += "   Concluded:  " + concluded + "\n";
		}
		register_product( cpe: cpe, location: "/", port: port, service: "ftp" );
	}
}
report = build_detection_report( app: "SolarWinds Serv-U", version: detected_version, cpe: cpe, install: "/" );
if(extra){
	report += "\n\nDetection methods:\n";
	report += extra;
}
if(report){
	log_message( port: 0, data: report );
}
exit( 0 );

