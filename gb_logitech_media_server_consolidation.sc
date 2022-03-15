if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108519" );
	script_version( "$Revision: 12903 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-12-28 20:34:35 +0100 (Fri, 28 Dec 2018) $" );
	script_tag( name: "creation_date", value: "2018-12-28 16:59:45 +0100 (Fri, 28 Dec 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Logitech SqueezeCenter/Media Server Detection Consolidation" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "gb_logitech_media_server_cli_detect.sc", "gb_logitech_media_server_detect.sc", "gb_logitech_media_server_udp_detect.sc", "gb_logitech_media_server_tcp_detect.sc" );
	script_mandatory_keys( "logitech/squeezecenter/detected" );
	script_xref( name: "URL", value: "http://mysqueezebox.com/" );
	script_tag( name: "summary", value: "The script reports a detected Logitech SqueezeCenter/Media Server including the
  version number and exposed services." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
if(!get_kb_item( "logitech/squeezecenter/detected" )){
	exit( 0 );
}
detected_version = "unknown";
for source in make_list( "http",
	 "cli",
	 "udp",
	 "tcp" ) {
	version_list = get_kb_list( "logitech/squeezecenter/" + source + "/*/version" );
	for version in version_list {
		if(version != "unknown" && detected_version == "unknown"){
			detected_version = version;
			set_kb_item( name: "logitech/squeezecenter/version", value: version );
			break;
		}
	}
}
cpe = "cpe:/a:logitech:media_server";
if(detected_version != "unknown"){
	cpe += ":" + detected_version;
}
location = "/";
if(http_ports = get_kb_list( "logitech/squeezecenter/http/port" )){
	for port in http_ports {
		extra += "\nHTTP(s) on port " + port + "/tcp\n";
		concluded = get_kb_item( "logitech/squeezecenter/http/" + port + "/concluded" );
		if(concluded){
			extra += "Concluded: " + concluded + "\n";
		}
		register_product( cpe: cpe, location: location, port: port, service: "www" );
	}
}
if(cli_ports = get_kb_list( "logitech/squeezecenter/cli/port" )){
	for port in cli_ports {
		extra += "\nCLI banner on port " + port + "/tcp\n";
		concluded = get_kb_item( "logitech/squeezecenter/cli/" + port + "/concluded" );
		if(concluded){
			extra += "Concluded: " + concluded + "\n";
		}
		register_product( cpe: cpe, location: location, port: port, service: "squeezecenter_cli" );
	}
}
if(udp_ports = get_kb_list( "logitech/squeezecenter/udp/port" )){
	for port in udp_ports {
		extra += "\nUDP banner on port " + port + "/udp\n";
		concluded = get_kb_item( "logitech/squeezecenter/udp/" + port + "/concluded" );
		if(concluded){
			extra += "Concluded: " + concluded + "\n";
		}
		register_product( cpe: cpe, location: location, port: port, service: "squeezecenter", proto: "udp" );
	}
}
if(tcp_ports = get_kb_list( "logitech/squeezecenter/tcp/port" )){
	for port in tcp_ports {
		extra += "\nSlimProto TCP banner on port " + port + "/tcp\n";
		concluded = get_kb_item( "logitech/squeezecenter/tcp/" + port + "/concluded" );
		if(concluded){
			extra += "Concluded: " + concluded + "\n";
		}
		register_product( cpe: cpe, location: location, port: port, service: "squeezecenter", proto: "tcp" );
	}
}
report = build_detection_report( app: "Logitech SqueezeCenter/Media Server", version: detected_version, install: location, cpe: cpe );
if(extra){
	report += "\n\nDetection methods:\n" + extra;
}
log_message( port: 0, data: report );
exit( 0 );

