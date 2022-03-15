if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144367" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2020-08-07 03:22:05 +0000 (Fri, 07 Aug 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Aerospike Database Detection Consolidation" );
	script_tag( name: "summary", value: "Consolidation of Aerospike Database detections." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_aerospike_xdr_detect.sc", "gb_aerospike_telnet_detect.sc" );
	script_mandatory_keys( "aerospike/detected" );
	script_xref( name: "URL", value: "https://www.aerospike.com/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!get_kb_item( "aerospike/detected" )){
	exit( 0 );
}
detected_version = "unknown";
location = "/";
for source in make_list( "xdr",
	 "telnet" ) {
	version_list = get_kb_list( "aerospike/" + source + "/*/version" );
	for version in version_list {
		if(version != "unknown" && detected_version == "unknown"){
			detected_version = version;
			break;
		}
	}
}
app_name = "Aerospike Database Server";
if(edition = get_kb_item( "aerospike/edition" )){
	app_name += " " + edition;
}
cpe = build_cpe( value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:aerospike:database_server:" );
if(!cpe){
	cpe = "cpe:/a:aerospike:database_server";
}
os_register_and_report( os: "Linux", cpe: "cpe:/o:linux:kernel", desc: "Aerospike Database Detection Consolidation", runs_key: "unixoide" );
if(xdr_ports = get_kb_list( "aerospike/xdr/port" )){
	for port in xdr_ports {
		extra += "Aerospike XDR on port " + port + "/tcp\n";
		concluded = get_kb_item( "aerospike/xdr/" + port + "/concluded" );
		if(concluded){
			extra += "  Concluded from version/product identification result: " + concluded + "\n";
		}
		register_product( cpe: cpe, location: location, port: port, service: "aerospike_xdr" );
	}
}
if(telnet_ports = get_kb_list( "aerospike/telnet/port" )){
	for port in telnet_ports {
		extra += "Aerospike Telnet on port " + port + "/tcp\n";
		concluded = get_kb_item( "aerospike/telnet/" + port + "/concluded" );
		if(concluded){
			extra += "  Concluded from version/product identification result: " + concluded + "\n";
		}
		register_product( cpe: cpe, location: location, port: port, service: "aerospike_telnet" );
	}
}
report = build_detection_report( app: app_name, version: detected_version, install: location, cpe: cpe );
if(extra){
	report += "\n\nDetection methods:\n";
	report += "\n" + extra;
}
log_message( port: 0, data: chomp( report ) );
exit( 0 );

