if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108806" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-06-17 07:04:17 +0000 (Wed, 17 Jun 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Geneko Router Detection (Telnet)" );
	script_tag( name: "summary", value: "Telnet based detection of Geneko routers." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/geneko/router/detected" );
	exit( 0 );
}
require("telnet_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("dump.inc.sc");
port = telnet_get_port( default: 23 );
banner = telnet_get_banner( port: port );
if(concl = egrep( string: banner, pattern: "geneko login:", icase: TRUE )){
	version = "unknown";
	model = "unknown";
	concl = bin2string( ddata: chomp( concl ) );
	set_kb_item( name: "geneko/router/detected", value: TRUE );
	set_kb_item( name: "geneko/router/telnet/port", value: port );
	set_kb_item( name: "geneko/router/telnet/" + port + "/concluded", value: concl );
	set_kb_item( name: "geneko/router/telnet/" + port + "/version", value: version );
	set_kb_item( name: "geneko/router/telnet/" + port + "/model", value: model );
}
exit( 0 );

