if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108347" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2018-02-26 12:49:56 +0100 (Mon, 26 Feb 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "NetEx HyperIP Detection Consolidation" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "gb_hyperip_http_detect.sc", "gb_hyperip_snmp_detect.sc", "gb_hyperip_ssh_banner_detect.sc", "gb_hyperip_ssh_login_detect.sc" );
	script_mandatory_keys( "hyperip/detected" );
	script_xref( name: "URL", value: "http://www.netex.com/hyperip" );
	script_tag( name: "summary", value: "The script reports a detected NetEx HyperIP virtual appliance including the
  version number and exposed services." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!get_kb_item( "hyperip/detected" )){
	exit( 0 );
}
detected_version = "unknown";
for source in make_list( "ssh-login",
	 "ssh-banner",
	 "http",
	 "snmp" ) {
	version_list = get_kb_list( "hyperip/" + source + "/*/version" );
	for version in version_list {
		if(version != "unknown" && detected_version == "unknown"){
			detected_version = version;
			set_kb_item( name: "hyperip/version", value: version );
		}
	}
}
if( detected_version != "unknown" ){
	app_cpe = "cpe:/a:netex:hyperip:" + detected_version;
	os_cpe = "cpe:/o:netex:hyperip:" + detected_version;
	os_name = "NetEx HyperIP " + detected_version;
}
else {
	app_cpe = "cpe:/a:netex:hyperip";
	os_cpe = "cpe:/o:netex:hyperip";
	os_name = "NetEx HyperIP";
}
os_register_and_report( os: os_name, cpe: os_cpe, desc: "NetEx HyperIP Detection Consolidation", runs_key: "unixoide" );
location = "/";
if(ssh_login_ports = get_kb_list( "hyperip/ssh-login/port" )){
	for port in ssh_login_ports {
		concluded = get_kb_item( "hyperip/ssh-login/" + port + "/concluded" );
		extra += "\nSSH login on port " + port + "/tcp\n";
		if(concluded){
			extra += "Concluded: " + concluded + "\n";
		}
		register_product( cpe: app_cpe, location: location, port: port, service: "ssh-login" );
		register_product( cpe: os_cpe, location: location, port: port, service: "ssh-login" );
	}
}
if(ssh_banner_ports = get_kb_list( "hyperip/ssh-banner/port" )){
	for port in ssh_banner_ports {
		concluded = get_kb_item( "hyperip/ssh-banner/" + port + "/concluded" );
		extra += "\nSSH-Banner on port " + port + "/tcp\n";
		if(concluded){
			extra += "Concluded: " + concluded + "\n";
		}
		register_product( cpe: app_cpe, location: location, port: port, service: "ssh-banner" );
		register_product( cpe: os_cpe, location: location, port: port, service: "ssh-banner" );
	}
}
if(http_ports = get_kb_list( "hyperip/http/port" )){
	for port in http_ports {
		concluded = get_kb_item( "hyperip/http/" + port + "/concluded" );
		concludedUrl = get_kb_item( "hyperip/http/" + port + "/concludedUrl" );
		extra += "\nHTTP(s) on port " + port + "/tcp\n";
		if( concluded && concludedUrl ){
			extra += "Concluded: " + concluded + " from URL: " + concludedUrl + "\n";
		}
		else {
			if(concluded){
				extra += "Concluded: " + concluded + "\n";
			}
		}
		register_product( cpe: app_cpe, location: location, port: port, service: "www" );
		register_product( cpe: os_cpe, location: location, port: port, service: "www" );
	}
}
if(snmp_ports = get_kb_list( "hyperip/snmp/port" )){
	for port in snmp_ports {
		concluded = get_kb_item( "hyperip/snmp/" + port + "/concluded" );
		extra += "\nSNMP on port " + port + "/udp\n";
		if(concluded){
			extra += "Concluded from SNMP sysDescr OID: " + concluded + "\n";
		}
		register_product( cpe: app_cpe, location: location, port: port, service: "snmp", proto: "udp" );
		register_product( cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp" );
	}
}
report = build_detection_report( app: "NetEx HyperIP", version: detected_version, install: location, cpe: app_cpe );
report += "\n\n";
report += build_detection_report( app: "NetEx HyperIP", version: detected_version, install: location, cpe: os_cpe );
if(extra){
	report += "\n\nDetection methods:\n";
	report += extra;
}
log_message( port: 0, data: report );
exit( 0 );

