if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103220" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-08-23 15:25:10 +0200 (Tue, 23 Aug 2011)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Greenbone Security Manager (GSM) / Greenbone OS (GOS) Detection Consolidation" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_greenbone_os_detect_http.sc", "gb_greenbone_os_detect_snmp.sc", "gb_greenbone_os_detect_ssh.sc" );
	script_mandatory_keys( "greenbone/gos/detected" );
	script_tag( name: "summary", value: "Consolidation of Greenbone Security Manager (GSM) /
  Greenbone OS (GOS) detections." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
SCRIPT_DESC = "Greenbone Security Manager (GSM) / Greenbone OS (GOS) Detection (Version)";
if(!get_kb_item( "greenbone/gos/detected" )){
	exit( 0 );
}
detected_version = "unknown";
detected_type = "unknown";
for source in make_list( "http",
	 "snmp",
	 "ssh" ) {
	version_list = get_kb_list( "greenbone/gos/" + source + "/*/version" );
	for version in version_list {
		if(version != "unknown" && detected_version == "unknown"){
			detected_version = version;
			set_kb_item( name: "greenbone/gos/version", value: version );
			break;
		}
	}
	type_list = get_kb_list( "greenbone/gsm/" + source + "/*/type" );
	for type in type_list {
		if(type != "unknown" && detected_type == "unknown"){
			detected_type = type;
			set_kb_item( name: "greenbone/gsm/type", value: type );
			break;
		}
	}
}
if( detected_type != "unknown" ){
	if( egrep( string: detected_type, pattern: "(TRIAL|DEMO|ONE|MAVEN|150V|EXPO|25V|CE|CENO|DECA|TERA|PETA|EXA)", icase: TRUE ) ) {
		hw_app_cpe = "cpe:/a:greenbone:gsm_" + tolower( detected_type );
	}
	else {
		hw_app_cpe = "cpe:/h:greenbone:gsm_" + tolower( detected_type );
	}
	app_type = detected_type;
}
else {
	hw_app_cpe = "cpe:/h:greenbone:gsm_unknown_type";
	app_type = "Unknown Type";
}
os_cpe = "cpe:/o:greenbone:greenbone_os";
if( detected_version != "unknown" ){
	os_register_and_report( os: "Greenbone OS (GOS)", version: detected_version, cpe: os_cpe, desc: SCRIPT_DESC, runs_key: "unixoide" );
	os_cpe += ":" + detected_version;
}
else {
	os_register_and_report( os: "Greenbone OS (GOS)", cpe: os_cpe, desc: SCRIPT_DESC, runs_key: "unixoide" );
}
location = "/";
if(http_port = get_kb_list( "greenbone/gos/http/port" )){
	for port in http_port {
		concluded = get_kb_item( "greenbone/gos/http/" + port + "/concluded" );
		concludedUrl = get_kb_item( "greenbone/gos/http/" + port + "/concludedUrl" );
		extra += "\n- HTTP(s) on port " + port + "/tcp";
		if(concluded){
			concluded = str_replace( string: concluded, find: "\n", replace: "<newline>" );
			extra += "\n  Concluded from version/product identification result: " + concluded;
		}
		if(concludedUrl){
			extra += "\n  Concluded from version/product identification location: " + concludedUrl;
		}
		register_product( cpe: hw_app_cpe, location: location, port: port, service: "www" );
		register_product( cpe: os_cpe, location: location, port: port, service: "www" );
	}
}
if(ssh_port = get_kb_list( "greenbone/gos/ssh/port" )){
	for port in ssh_port {
		concluded = get_kb_item( "greenbone/gos/ssh/" + port + "/concluded" );
		extra += "\n- SSH on port " + port + "/tcp";
		if(concluded){
			extra += "\n  Concluded from SSH banner / login: " + concluded;
		}
		register_product( cpe: hw_app_cpe, location: location, port: port, service: "ssh" );
		register_product( cpe: os_cpe, location: location, port: port, service: "ssh" );
	}
}
if(snmp_port = get_kb_list( "greenbone/gos/snmp/port" )){
	for port in snmp_port {
		concluded = get_kb_item( "greenbone/gos/snmp/" + port + "/concluded" );
		concludedOID = get_kb_item( "greenbone/gos/snmp/" + port + "/concludedOID" );
		extra += "\n- SNMP on port " + port + "/udp";
		if( concluded && concludedOID ) {
			extra += "\n  Concluded from " + concluded + " via OID: " + concludedOID;
		}
		else {
			if(concluded){
				extra += "\n  Concluded from SNMP sysDescr OID: " + concluded;
			}
		}
		register_product( cpe: hw_app_cpe, location: location, port: port, service: "snmp", proto: "udp" );
		register_product( cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp" );
	}
}
report = build_detection_report( app: "Greenbone OS (GOS)", version: detected_version, install: location, cpe: os_cpe );
report += "\n\n" + build_detection_report( app: "Greenbone Security Manager (GSM) " + app_type, install: location, cpe: hw_app_cpe, skip_version: TRUE );
if(extra){
	report += "\n\nDetection methods:\n";
	report += extra;
}
log_message( port: 0, data: report );
exit( 0 );

