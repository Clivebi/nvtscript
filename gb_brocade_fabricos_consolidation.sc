if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108335" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2018-02-15 11:09:51 +0100 (Thu, 15 Feb 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Brocade Fabric OS Detection Consolidation" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "gb_brocade_fabricos_telnet_detect.sc", "gb_brocade_fabricos_http_detect.sc", "gb_brocade_fabricos_snmp_detect.sc" );
	script_mandatory_keys( "brocade_fabricos/detected" );
	script_xref( name: "URL", value: "http://www.brocade.com/en/products-services/storage-networking/fibre-channel.html" );
	script_tag( name: "summary", value: "The script reports a detected device running Brocade Fabric OS
  including the version number and exposed services." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!get_kb_item( "brocade_fabricos/detected" )){
	exit( 0 );
}
detected_version = "unknown";
for source in make_list( "telnet",
	 "http",
	 "snmp" ) {
	version_list = get_kb_list( "brocade_fabricos/" + source + "/*/version" );
	for version in version_list {
		if(version != "unknown" && detected_version == "unknown"){
			detected_version = version;
			set_kb_item( name: "brocade_fabricos/version", value: version );
		}
	}
}
if( detected_version != "unknown" ){
	cpe = "cpe:/o:brocade:fabric_os:" + detected_version;
	os_name = "Brocade Fabric OS " + detected_version;
}
else {
	cpe = "cpe:/o:brocade:fabric_os";
	os_name = "Brocade Fabric OS";
}
os_register_and_report( os: os_name, cpe: cpe, desc: "Brocade Fabric OS Detection Consolidation", runs_key: "unixoide" );
location = "/";
if(telnet_port = get_kb_list( "brocade_fabricos/telnet/port" )){
	for port in telnet_port {
		concluded = get_kb_item( "brocade_fabricos/telnet/" + port + "/concluded" );
		extra += "\nTelnet on port " + port + "/tcp\n";
		if(concluded){
			extra += "Concluded: " + concluded + "\n";
		}
		register_product( cpe: cpe, location: location, port: port, service: "telnet" );
	}
}
if(http_port = get_kb_list( "brocade_fabricos/http/port" )){
	for port in http_port {
		concluded = get_kb_item( "brocade_fabricos/http/" + port + "/concluded" );
		concludedUrl = get_kb_item( "brocade_fabricos/http/" + port + "/concludedUrl" );
		extra += "\nHTTP(s) on port " + port + "/tcp\n";
		if(concluded && concludedUrl){
			extra += "Concluded: " + concluded + " from URL: " + concludedUrl + "\n";
		}
		register_product( cpe: cpe, location: location, port: port, service: "www" );
	}
}
if(snmp_port = get_kb_list( "brocade_fabricos/snmp/port" )){
	for port in snmp_port {
		concluded = get_kb_item( "brocade_fabricos/snmp/" + port + "/concluded" );
		concludedOID = get_kb_item( "brocade_fabricos/snmp/" + port + "/concludedOID" );
		extra += "\nSNMP on port " + port + "/udp\n";
		if(concluded && concludedOID){
			extra += "Concluded from " + concluded + " via OID: " + concludedOID + "\n";
		}
		register_product( cpe: cpe, location: location, port: port, service: "snmp", proto: "udp" );
	}
}
report = build_detection_report( app: "Brocade Fabric OS", version: detected_version, install: location, cpe: cpe );
if(extra){
	report += "\n\nDetection methods:\n";
	report += extra;
}
log_message( port: 0, data: report );
exit( 0 );

