require("plugin_feed_info.inc.sc");
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141923" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2019-01-25 12:54:35 +0700 (Fri, 25 Jan 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "NetApp Data ONTAP Detection Consolidation" );
	script_tag( name: "summary", value: "The script reports a detected NetApp Data ONTAP including the version
number." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_netapp_data_ontap_http_detect.sc", "gb_netapp_data_ontap_ntp_detect.sc", "gb_netapp_data_ontap_snmp_detect.sc" );
	if(FEED_NAME == "GSF" || FEED_NAME == "SCM"){
		script_dependencies( "gsf/gb_netapp_data_ontap_ftp_detect.sc", "gsf/gb_netapp_data_ontap_ndmp_detect.sc", "gsf/gb_netapp_data_ontap_ssh_detect.sc", "gsf/gb_netapp_data_ontap_telnet_detect.sc", "gsf/gb_netapp_data_ontap_ssh_login_detect.sc" );
	}
	script_mandatory_keys( "netapp_data_ontap/detected" );
	script_xref( name: "URL", value: "http://www.netapp.com/us/products/data-management-software/ontap.asp" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!get_kb_item( "netapp_data_ontap/detected" )){
	exit( 0 );
}
detected_version = "unknown";
for source in make_list( "http",
	 "ntp",
	 "snmp",
	 "ssh-login",
	 "ndmp",
	 "telnet",
	 "ssh",
	 "ftp" ) {
	version_list = get_kb_list( "netapp_data_ontap/" + source + "/*/version" );
	for vers in version_list {
		if(vers != "unknown" && detected_version == "unknown"){
			detected_version = vers;
		}
	}
}
cpe = build_cpe( value: tolower( detected_version ), exp: "^([0-9p.]+)", base: "cpe:/o:netapp:data_ontap:" );
if(!cpe){
	cpe = "cpe:/o:netapp:data_ontap";
}
if(http_ports = get_kb_list( "netapp_data_ontap/http/port" )){
	for port in http_ports {
		extra += "HTTP(s) on port " + port + "/tcp\n";
		concluded = get_kb_item( "netapp_data_ontap/http/" + port + "/concluded" );
		if(concluded){
			extra += "Concluded from: " + concluded + "\n";
		}
		register_product( cpe: cpe, location: "/", port: port, service: "www" );
	}
}
if(ntp_ports = get_kb_list( "netapp_data_ontap/ntp/port" )){
	for port in ntp_ports {
		extra += "NTP on port " + port + "/udp\n";
		concluded = get_kb_item( "netapp_data_ontap/ntp/" + port + "/concluded" );
		if(concluded){
			extra += "Concluded from NTP system banner: " + concluded + "\n";
		}
		register_product( cpe: cpe, location: "/", port: port, service: "ntp", proto: "udp" );
	}
}
if(snmp_ports = get_kb_list( "netapp_data_ontap/snmp/port" )){
	for port in snmp_ports {
		extra += "SNMP on port " + port + "/udp\n";
		concluded = get_kb_item( "netapp_data_ontap/snmp/" + port + "/concluded" );
		if(concluded){
			extra += "Concluded from SNMP sysDescr OID: " + concluded + "\n";
		}
		register_product( cpe: cpe, location: "/", port: port, service: "snmp", proto: "udp" );
	}
}
if(ndmp_ports = get_kb_list( "netapp_data_ontap/ndmp/port" )){
	for port in ndmp_ports {
		extra += "NDMP on port " + port + "/tcp\n";
		concluded = get_kb_item( "netapp_data_ontap/ndmp/" + port + "/concluded" );
		if(concluded){
			extra += "Concluded from NDMP host info: " + concluded + "\n";
		}
		register_product( cpe: cpe, location: "/", port: port, service: "ndmp" );
	}
}
if(telnet_ports = get_kb_list( "netapp_data_ontap/telnet/port" )){
	for port in telnet_ports {
		extra += "Telnet banner on port " + port + "/tcp\n";
		concluded = get_kb_item( "netapp_data_ontap/telnet/" + port + "/concluded" );
		if(concluded){
			extra += "Concluded from: " + concluded + "\n";
		}
		register_product( cpe: cpe, location: "/", port: port, service: "telnet" );
	}
}
if(ssh_ports = get_kb_list( "netapp_data_ontap/ssh/port" )){
	for port in ssh_ports {
		extra += "SSH banner on port " + port + "/tcp\n";
		concluded = get_kb_item( "netapp_data_ontap/ssh/" + port + "/concluded" );
		if(concluded){
			extra += "Concluded from: " + concluded + "\n";
		}
		register_product( cpe: cpe, location: "/", port: port, service: "ssh" );
	}
}
if(ftp_ports = get_kb_list( "netapp_data_ontap/ftp/port" )){
	for port in ftp_ports {
		extra += "FTP banner on port " + port + "/tcp\n";
		concluded = get_kb_item( "netapp_data_ontap/ftp/" + port + "/concluded" );
		if(concluded){
			extra += "Concluded from: " + concluded + "\n";
		}
		register_product( cpe: cpe, location: "/", port: port, service: "ftp" );
	}
}
if(ssh_login_ports = get_kb_list( "netapp_data_ontap/ssh-login/port" )){
	for port in ssh_login_ports {
		extra += "SSH login on port " + port + "/tcp\n";
		concluded = get_kb_item( "netapp_data_ontap/ssh-login/" + port + "/concluded" );
		if(concluded){
			extra += "Concluded " + concluded + "\n";
		}
		register_product( cpe: cpe, location: "/", port: port, service: "ssh-login" );
	}
}
os_register_and_report( os: "NetApp Data ONTAP", cpe: cpe, desc: "NetApp Data ONTAP Detection Consolidation", runs_key: "unixoide" );
report = build_detection_report( app: "NetApp Data ONTAP", version: detected_version, cpe: cpe, install: "/" );
if(extra){
	report += "\n\nDetection methods:\n";
	report += "\r\n" + extra;
}
if(report){
	log_message( port: 0, data: report );
}
exit( 0 );

