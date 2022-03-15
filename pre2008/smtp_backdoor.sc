if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.18391" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_name( "SMTP Server on non standard port" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Michel Arboi" );
	script_family( "Malware" );
	script_dependencies( "smtpserver_detect.sc" );
	script_require_ports( "Services/smtp", 25 );
	script_mandatory_keys( "smtp/banner/available" );
	script_tag( name: "solution", value: "Check and clean your configuration." );
	script_tag( name: "summary", value: "This SMTP server is running on a non standard port.

  This might be a backdoor set up by attackers to send spam or even control the system." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("smtp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = smtp_get_port( default: 25 );
if(port && port != 25 && port != 465 && port != 587){
	security_message( port: port );
}

