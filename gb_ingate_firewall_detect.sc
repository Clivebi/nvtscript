if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103207" );
	script_version( "2021-04-14T08:50:25+0000" );
	script_tag( name: "last_modification", value: "2021-04-14 08:50:25 +0000 (Wed, 14 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-08-17 15:40:19 +0200 (Wed, 17 Aug 2011)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "inGate Firewall Detection (SIP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "sip_detection.sc", "sip_detection_tcp.sc" );
	script_mandatory_keys( "sip/banner/available" );
	script_xref( name: "URL", value: "http://www.ingate.com/Products_firewalls.php" );
	script_tag( name: "summary", value: "This host is an inGate Firewall." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("sip.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
infos = sip_get_port_proto( default_port: "5060", default_proto: "udp" );
port = infos["port"];
proto = infos["proto"];
banner = sip_get_banner( port: port, proto: proto );
if(!banner || !ContainsString( banner, "Ingate-Firewall/" )){
	exit( 0 );
}
vers = "unknown";
version = eregmatch( pattern: "Ingate-Firewall/([0-9.]+)", string: banner );
if(!isnull( version[1] )){
	vers = version[1];
}
set_kb_item( name: "Ingate_Firewall/detected", value: TRUE );
set_kb_item( name: port + "/Ingate_Firewall", value: vers );
if( vers == "unknown" ){
	cpe = "cpe:/h:ingate:ingate_firewall";
}
else {
	cpe = "cpe:/h:ingate:ingate_firewall:" + vers;
}
location = port + "/" + proto;
register_product( cpe: cpe, port: port, location: location, service: "sip", proto: proto );
log_message( data: build_detection_report( app: "inGate Firewall", version: vers, install: location, cpe: cpe, concluded: version[0] ), port: port, proto: proto );
exit( 0 );

