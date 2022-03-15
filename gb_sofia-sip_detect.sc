if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113672" );
	script_version( "2021-04-14T08:50:25+0000" );
	script_tag( name: "last_modification", value: "2021-04-14 08:50:25 +0000 (Wed, 14 Apr 2021)" );
	script_tag( name: "creation_date", value: "2020-04-09 11:40:00 +0100 (Thu, 09 Apr 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Sofia-SIP Library Detection (SIP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "sip_detection.sc", "sip_detection_tcp.sc" );
	script_mandatory_keys( "sip/banner/available" );
	script_tag( name: "summary", value: "Checks whether the Sofia-SIP Library is present on
  the target system and if so, tries to figure out the installed version." );
	script_xref( name: "URL", value: "http://sofia-sip.sourceforge.net/" );
	exit( 0 );
}
CPE = "cpe:/a:sofia-sip:sofia-sip:";
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("sip.inc.sc");
require("cpe.inc.sc");
infos = sip_get_port_proto( default_port: "5060", default_proto: "udp" );
port = infos["port"];
proto = infos["proto"];
banner = sip_get_banner( port: port, proto: proto );
if(IsMatchRegexp( banner, "sofia-sip" )){
	set_kb_item( name: "sofia-sip/detected", value: TRUE );
	version = "unknown";
	ver = eregmatch( string: banner, pattern: "sofia-sip/([0-9.]+)" );
	if(!isnull( ver[1] )){
		version = ver[1];
	}
	register_and_report_cpe( app: "Sofia-SIP Library", ver: version, concluded: ver[0], base: CPE, expr: "([0-9.]+)", insloc: port + "/" + proto, regPort: port, regProto: proto, regService: "sip" );
}
exit( 0 );

