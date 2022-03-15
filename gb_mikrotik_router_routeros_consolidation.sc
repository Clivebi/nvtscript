if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810608" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2017-03-09 15:28:48 +0530 (Thu, 09 Mar 2017)" );
	script_name( "MikroTik RouterOS Detection Consolidation" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_mikrotik_router_routeros_ftp_detect.sc", "gb_mikrotik_router_routeros_telnet_detect.sc", "gb_mikrotik_router_routeros_webui_detect.sc", "gb_mikrotik_router_routeros_ssh_detect.sc", "gb_mikrotik_router_routeros_pptp_detect.sc" );
	script_mandatory_keys( "mikrotik/detected" );
	script_tag( name: "summary", value: "Detection of MikroTik RouterOS.

  The script sends a connection request to the server and attempts to
  detect the presence of MikroTik Router." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
CPE = "cpe:/o:mikrotik:routeros";
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!get_kb_item( "mikrotik/detected" )){
	exit( 0 );
}
location = "/";
detected_version = "unknown";
for source in make_list( "ftp",
	 "telnet",
	 "webui",
	 "ssh",
	 "pptp" ) {
	if(detected_version != "unknown"){
		break;
	}
	version_list = get_kb_list( "mikrotik/" + source + "/*/version" );
	for version in version_list {
		if(version != "unknown" && detected_version == "unknown"){
			detected_version = version;
			set_kb_item( name: "mikrotik/version", value: version );
			if(temp_cpe = build_cpe( value: detected_version, exp: "([A-Za-z0-9.]+)", base: CPE + ":" )){
				CPE = temp_cpe;
			}
			break;
		}
	}
}
if(webui_ports = get_kb_list( "mikrotik/webui/port" )){
	for port in webui_ports {
		concluded = get_kb_item( "mikrotik/webui/" + port + "/concluded" );
		extra += "HTTP(s) on port " + port + "/tcp\n";
		if(concluded){
			extra += "Concluded from: " + concluded + "\n";
		}
		register_product( cpe: CPE, location: location, port: port, service: "www" );
	}
}
if(telnet_ports = get_kb_list( "mikrotik/telnet/port" )){
	for port in telnet_ports {
		concluded = get_kb_item( "mikrotik/telnet/" + port + "/concluded" );
		extra += "Telnet banner on port " + port + "/tcp\n";
		if(concluded){
			extra += "Concluded from: " + concluded + "\n";
		}
		register_product( cpe: CPE, location: location, port: port, service: "telnet" );
	}
}
if(ftp_ports = get_kb_list( "mikrotik/ftp/port" )){
	for port in ftp_ports {
		concluded = get_kb_item( "mikrotik/ftp/" + port + "/concluded" );
		extra += "FTP banner on port " + port + "/tcp\n";
		if(concluded){
			extra += "Concluded from: " + concluded + "\n";
		}
		register_product( cpe: CPE, location: location, port: port, service: "ftp" );
	}
}
if(ssh_ports = get_kb_list( "mikrotik/ssh/port" )){
	for port in ssh_ports {
		concluded = get_kb_item( "mikrotik/ssh/" + port + "/concluded" );
		extra += "SSH banner on port " + port + "/tcp\n";
		if(concluded){
			extra += "Concluded from: " + concluded + "\n";
		}
		register_product( cpe: CPE, location: location, port: port, service: "ssh" );
	}
}
if(pptp_ports = get_kb_list( "mikrotik/pptp/port" )){
	for port in pptp_ports {
		concluded = get_kb_item( "mikrotik/pptp/" + port + "/concluded" );
		extra += "PPTP vendor string on port " + port + "/tcp\n";
		if(concluded){
			extra += "Concluded from: " + concluded + "\n";
		}
		register_product( cpe: CPE, location: location, port: port, service: "pptp" );
	}
}
if( version != "unknown" ) {
	os_register_and_report( os: "Mikrotik Router OS", version: version, cpe: "cpe:/o:mikrotik:routeros", desc: "MikroTik RouterOS Detection Consolidation", runs_key: "unixoide" );
}
else {
	os_register_and_report( os: "Mikrotik Router OS", cpe: CPE, desc: "MikroTik RouterOS Detection Consolidation", runs_key: "unixoide" );
}
report = build_detection_report( app: "Mikrotik Router OS", version: detected_version, install: location, cpe: CPE );
if(extra){
	report += "\n\nDetection methods:\n";
	report += "\n" + extra;
}
log_message( port: 0, data: report );
exit( 0 );

