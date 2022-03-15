if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106325" );
	script_version( "2021-04-14T08:50:25+0000" );
	script_tag( name: "last_modification", value: "2021-04-14 08:50:25 +0000 (Wed, 14 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-10-04 13:39:10 +0700 (Tue, 04 Oct 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Yealink IP Phone Detection (SIP)" );
	script_tag( name: "summary", value: "Detection of Yealink IP Phone.

  The script attempts to identify Yealink IP Phone via SIP banner to extract the model and version
  number." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "sip_detection.sc", "sip_detection_tcp.sc" );
	script_mandatory_keys( "sip/banner/available" );
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
if(banner && IsMatchRegexp( banner, "Yealink SIP" )){
	version = "unknown";
	model = "unknown";
	set_kb_item( name: "yealink_ipphone/detected", value: TRUE );
	set_kb_item( name: "yealink_ipphone/sip/detected", value: TRUE );
	set_kb_item( name: "yealink_ipphone/sip/port", value: port );
	set_kb_item( name: "yealink_ipphone/sip/" + port + "/proto", value: proto );
	set_kb_item( name: "yealink_ipphone/sip/" + port + "/concluded", value: banner );
	mo = eregmatch( pattern: "SIP-([A-Z0-9_]+)", string: banner );
	if(!isnull( mo[1] )){
		model = mo[1];
		vers = eregmatch( pattern: model + " ([0-9.]+)", string: banner );
		if(!isnull( vers[1] )){
			version = vers[1];
		}
	}
	set_kb_item( name: "yealink_ipphone/sip/" + port + "/version", value: version );
	set_kb_item( name: "yealink_ipphone/sip/" + port + "/model", value: model );
}
exit( 0 );

