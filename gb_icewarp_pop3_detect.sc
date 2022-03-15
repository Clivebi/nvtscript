if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113775" );
	script_version( "2020-11-04T13:41:39+0000" );
	script_tag( name: "last_modification", value: "2020-11-04 13:41:39 +0000 (Wed, 04 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-11-04 10:10:10 +0100 (Wed, 04 Nov 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "IceWarp Mail Server Detection (POP3)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "popserver_detect.sc" );
	script_require_ports( "Services/pop3", 110 );
	script_mandatory_keys( "pop3/icewarp/mailserver/detected" );
	script_tag( name: "summary", value: "POP3 based detection of IceWarp Mail Server." );
	exit( 0 );
}
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("pop3_func.inc.sc");
require("port_service_func.inc.sc");
port = pop3_get_port( default: 110 );
if(!banner = pop3_get_banner( port: port )){
	exit( 0 );
}
if(IsMatchRegexp( banner, "IceWarp" )){
	replace_kb_item( name: "icewarp/mailserver/detected", value: TRUE );
	replace_kb_item( name: "icewarp/mailserver/pop3/detected", value: TRUE );
	set_kb_item( name: "icewarp/mailserver/pop3/port", value: port );
	version = "unknown";
	vers = eregmatch( string: banner, pattern: "IceWarp ([0-9.]+)", icase: TRUE );
	if(!isnull( vers[1] )){
		version = vers[1];
		set_kb_item( name: "icewarp/mailserver/pop3/" + port + "/concluded", value: vers[0] );
	}
	set_kb_item( name: "icewarp/mailserver/pop3/" + port + "/version", value: version );
}
exit( 0 );

