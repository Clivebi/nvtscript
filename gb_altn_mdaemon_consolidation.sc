require("plugin_feed_info.inc.sc");
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145329" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-02-08 04:38:39 +0000 (Mon, 08 Feb 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Alt-N MDaemon Mail Server Detection Consolidation" );
	script_tag( name: "summary", value: "Consolidation of Alt-N MDaemon Mail Server detections." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_altn_mdaemon_http_detect.sc" );
	if(FEED_NAME == "GSF" || FEED_NAME == "SCM"){
		script_dependencies( "gsf/gb_altn_mdaemon_pop3_detect.sc", "gsf/gb_altn_mdaemon_imap_detect.sc", "gsf/gb_altn_mdaemon_smtp_detect.sc" );
	}
	script_mandatory_keys( "altn/mdaemon/detected" );
	script_xref( name: "URL", value: "https://www.altn.com/Products/MDaemon-Email-Server-Windows/" );
	exit( 0 );
}
if(!get_kb_item( "altn/mdaemon/detected" )){
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
detected_version = "unknown";
location = "/";
for source in make_list( "http",
	 "pop3",
	 "imap",
	 "smtp" ) {
	version_list = get_kb_list( "altn/mdaemon/" + source + "/*/version" );
	for version in version_list {
		if(version != "unknown" && detected_version == "unknown"){
			detected_version = version;
			break;
		}
	}
}
cpe = build_cpe( value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:alt-n:mdaemon:" );
if(!cpe){
	cpe = "cpe:/a:alt-n:mdaemon";
}
os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", desc: "Alt-N MDaemon Mail Server Detection Consolidation", runs_key: "windows" );
if(http_ports = get_kb_list( "altn/mdaemon/http/port" )){
	for port in http_ports {
		extra += "HTTP(s) on port " + port + "/tcp\n";
		concluded = get_kb_item( "altn/mdaemon/http/" + port + "/concluded" );
		if(concluded){
			extra += "  Concluded from version/product identification result: " + concluded + "\n";
		}
		register_product( cpe: cpe, location: location, port: port, service: "www" );
	}
}
if(pop3_ports = get_kb_list( "altn/mdaemon/pop3/port" )){
	for port in pop3_ports {
		extra += "POP3 on port " + port + "/tcp\n";
		concluded = get_kb_item( "altn/mdaemon/pop3/" + port + "/concluded" );
		if(concluded){
			extra += "  Concluded from version/product identification result: " + concluded + "\n";
		}
		register_product( cpe: cpe, location: location, port: port, service: "pop3" );
	}
}
if(imap_ports = get_kb_list( "altn/mdaemon/imap/port" )){
	for port in imap_ports {
		extra += "IMAP on port " + port + "/tcp\n";
		concluded = get_kb_item( "altn/mdaemon/imap/" + port + "/concluded" );
		if(concluded){
			extra += "  Concluded from version/product identification result: " + concluded + "\n";
		}
		register_product( cpe: cpe, location: location, port: port, service: "imap" );
	}
}
if(smtp_ports = get_kb_list( "altn/mdaemon/smtp/port" )){
	for port in smtp_ports {
		extra += "SMTP on port " + port + "/tcp\n";
		concluded = get_kb_item( "altn/mdaemon/smtp/" + port + "/concluded" );
		if(concluded){
			extra += "  Concluded from version/product identification result: " + concluded + "\n";
		}
		register_product( cpe: cpe, location: location, port: port, service: "smtp" );
	}
}
report = build_detection_report( app: "Alt-N MDaemon Mail Server", version: detected_version, install: location, cpe: cpe );
if(extra){
	report += "\n\nDetection methods:\n";
	report += "\n" + extra;
}
log_message( port: 0, data: report );
exit( 0 );

