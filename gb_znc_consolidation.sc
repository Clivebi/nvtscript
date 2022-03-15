if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144111" );
	script_version( "2020-06-25T12:09:11+0000" );
	script_tag( name: "last_modification", value: "2020-06-25 12:09:11 +0000 (Thu, 25 Jun 2020)" );
	script_tag( name: "creation_date", value: "2020-06-16 03:46:25 +0000 (Tue, 16 Jun 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "ZNC Consolidation" );
	script_tag( name: "summary", value: "Reports the ZNC version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_znc_http_detect.sc", "gb_znc_irc_detect.sc" );
	script_mandatory_keys( "znc/detected" );
	script_xref( name: "URL", value: "https://wiki.znc.in/ZNC" );
	exit( 0 );
}
if(!get_kb_item( "znc/detected" )){
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
detected_version = "unknown";
location = "/";
for source in make_list( "http",
	 "irc" ) {
	version_list = get_kb_list( "znc/" + source + "/*/version" );
	for version in version_list {
		if(version != "unknown" && detected_version == "unknown"){
			detected_version = version;
			break;
		}
	}
}
cpe = build_cpe( value: tolower( detected_version ), exp: "^([0-9.]+)", base: "cpe:/a:znc:znc:" );
if(!cpe){
	cpe = "cpe:/a:znc:znc";
}
if(http_ports = get_kb_list( "znc/http/port" )){
	for port in http_ports {
		extra += "HTTP(s) on port " + port + "/tcp\n";
		concluded = get_kb_item( "znc/http/" + port + "/concluded" );
		if(concluded){
			extra += "  Concluded from version/product identification result: " + concluded + "\n";
		}
		register_product( cpe: cpe, location: location, port: port, service: "www" );
	}
}
if(irc_ports = get_kb_list( "znc/irc/port" )){
	for port in irc_ports {
		extra += "IRC on port " + port + "/tcp\n";
		concluded = get_kb_item( "znc/irc/" + port + "/concluded" );
		if(concluded){
			extra += "  Concluded from version/product identification result: " + concluded + "\n";
		}
		register_product( cpe: cpe, location: location, port: port, service: "irc" );
	}
}
report = build_detection_report( app: "ZNC", version: detected_version, install: location, cpe: cpe );
if(extra){
	report += "\n\nDetection methods:\n";
	report += "\n" + chomp( extra );
}
log_message( port: 0, data: report );
exit( 0 );

