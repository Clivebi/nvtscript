if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113776" );
	script_version( "2020-11-04T13:41:39+0000" );
	script_tag( name: "last_modification", value: "2020-11-04 13:41:39 +0000 (Wed, 04 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-11-04 10:10:10 +0100 (Wed, 04 Nov 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "IceWarp Mail Server Detection (SMTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smtpserver_detect.sc" );
	script_require_ports( "Services/smtp", 25, 587 );
	script_mandatory_keys( "smtp/icewarp/mailserver/detected" );
	script_tag( name: "summary", value: "SMTP based detection of IceWarp Mail Server." );
	exit( 0 );
}
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("smtp_func.inc.sc");
require("port_service_func.inc.sc");
port = smtp_get_port( default: 25 );
if(!banner = smtp_get_banner( port: port )){
	exit( 0 );
}
if(IsMatchRegexp( banner, "IceWarp" )){
	replace_kb_item( name: "icewarp/mailserver/detected", value: TRUE );
	replace_kb_item( name: "icewarp/mailserver/smtp/detected", value: TRUE );
	set_kb_item( name: "icewarp/mailserver/smtp/port", value: port );
	version = "unknown";
	vers = eregmatch( string: banner, pattern: "IceWarp ([0-9.]+)", icase: TRUE );
	if(!isnull( vers[1] )){
		version = vers[1];
		set_kb_item( name: "icewarp/mailserver/smtp/" + port + "/concluded", value: vers[0] );
	}
	set_kb_item( name: "icewarp/mailserver/smtp/" + port + "/version", value: version );
}
exit( 0 );

