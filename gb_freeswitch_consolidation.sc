if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143231" );
	script_version( "2019-12-06T09:54:56+0000" );
	script_tag( name: "last_modification", value: "2019-12-06 09:54:56 +0000 (Fri, 06 Dec 2019)" );
	script_tag( name: "creation_date", value: "2019-12-06 06:51:25 +0000 (Fri, 06 Dec 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "FreeSWITCH Detection Consolidation" );
	script_tag( name: "summary", value: "The script reports a detected FreeSWITCH installation including the version
  number." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_freeswitch_sip_detect.sc", "gb_freeswitch_http_detect.sc", "gb_freeswitch_mod_event_socket_service_detect.sc" );
	script_mandatory_keys( "freeswitch/detected" );
	script_xref( name: "URL", value: "https://freeswitch.com/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
if(!get_kb_item( "freeswitch/detected" )){
	exit( 0 );
}
detected_version = "unknown";
for source in make_list( "sip",
	 "http" ) {
	version_list = get_kb_list( "freeswitch/" + source + "/*/version" );
	for version in version_list {
		if(version != "unknown" && detected_version == "unknown"){
			detected_version = version;
			break;
		}
	}
}
cpe = build_cpe( value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:freeswitch:freeswitch:" );
if(!cpe){
	cpe = "cpe:/a:freeswitch:freeswitch";
}
location = "/";
if(sip_ports = get_kb_list( "freeswitch/sip/tcp/port" )){
	for port in sip_ports {
		concluded = get_kb_item( "freeswitch/sip/tcp/" + port + "/concluded" );
		extra += "SIP on port " + port + "/tcp\n";
		extra += "  Concluded from version/product identification result: " + concluded + "\n";
		register_product( cpe: cpe, location: location, port: port, service: "sip", proto: "tcp" );
	}
}
if(sip_ports = get_kb_list( "freeswitch/sip/udp/port" )){
	for port in sip_ports {
		concluded = get_kb_item( "freeswitch/sip/udp/" + port + "/concluded" );
		extra += "SIP on port " + port + "/udp\n";
		extra += "  Concluded from version/product identification result: " + concluded + "\n";
		register_product( cpe: cpe, location: location, port: port, service: "sip", proto: "udp" );
	}
}
if(http_ports = get_kb_list( "freeswitch/http/port" )){
	for port in http_ports {
		extra += "HTTP(s) on port " + port + "/tcp\n";
		concluded = get_kb_item( "freeswitch/http/" + port + "/concluded" );
		concUrl = get_kb_item( "freeswitch/http/" + port + "/concUrl" );
		if(concluded){
			extra += "  Concluded from version/product identification result: " + concluded + "\n";
			extra += "  Concluded from version/product identification location: " + concUrl + "\n";
		}
		register_product( cpe: cpe, location: location, port: port, service: "www" );
	}
}
if(modevent_ports = get_kb_list( "freeswitch/mod_event_socket/port" )){
	for port in modevent_ports {
		extra += "mod_event_socket on port " + port + "/tcp\n";
	}
}
report = build_detection_report( app: "FreeSWITCH", version: detected_version, install: location, cpe: cpe );
if(extra){
	report += "\n\nDetection methods:\n";
	report += "\n" + extra;
}
log_message( port: 0, data: report );
exit( 0 );

