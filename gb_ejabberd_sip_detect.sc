if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144097" );
	script_version( "2021-04-14T08:50:25+0000" );
	script_tag( name: "last_modification", value: "2021-04-14 08:50:25 +0000 (Wed, 14 Apr 2021)" );
	script_tag( name: "creation_date", value: "2020-06-09 09:05:20 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "ejabberd Detection (SIP)" );
	script_tag( name: "summary", value: "Detection of ejabberd.

  SIP based detection of ejabberd." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "sip_detection.sc", "sip_detection_tcp.sc" );
	script_mandatory_keys( "sip/banner/available" );
	exit( 0 );
}
require("sip.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
infos = sip_get_port_proto( default_port: "5060", default_proto: "udp" );
port = infos["port"];
proto = infos["proto"];
banner = sip_get_banner( port: port, proto: proto );
if(banner && ContainsString( banner, "ejabberd" )){
	version = "unknown";
	set_kb_item( name: "ejabberd/detected", value: TRUE );
	set_kb_item( name: "ejabberd/sip/port", value: port );
	set_kb_item( name: "ejabberd/sip/" + port + "/proto", value: proto );
	set_kb_item( name: "ejabberd/sip/" + port + "/concluded", value: banner );
	vers = eregmatch( pattern: "ejabberd (.*)", string: banner );
	if(!isnull( vers[1] )){
		version = chomp( vers[1] );
	}
	set_kb_item( name: "ejabberd/sip/" + port + "/version", value: version );
}
exit( 0 );

