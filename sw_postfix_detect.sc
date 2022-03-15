if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111086" );
	script_version( "2020-08-24T15:40:14+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:40:14 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-02-04 17:00:00 +0100 (Thu, 04 Feb 2016)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Postfix SMTP Server Detection" );
	script_copyright( "Copyright (C) 2016 SCHUTZWERK GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_dependencies( "smtpserver_detect.sc" );
	script_mandatory_keys( "smtp/banner/available" );
	script_tag( name: "summary", value: "The script checks the SMTP server
  banner for the presence of Postfix." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("smtp_func.inc.sc");
require("cpe.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
ports = smtp_get_ports();
for port in ports {
	banner = smtp_get_banner( port: port );
	quit = get_kb_item( "smtp/fingerprints/" + port + "/quit_banner" );
	noop = get_kb_item( "smtp/fingerprints/" + port + "/noop_banner" );
	help = get_kb_item( "smtp/fingerprints/" + port + "/help_banner" );
	rset = get_kb_item( "smtp/fingerprints/" + port + "/rset_banner" );
	if(ContainsString( banner, "ESMTP Postfix" ) || ContainsString( banner, "Ubuntu/Postfix;" ) || ( ContainsString( quit, "Bye" ) && ContainsString( noop, "Ok" ) && ContainsString( help, "Error: command not recognized" ) && ContainsString( rset, "Ok" ) )){
		install = port + "/tcp";
		version = "unknown";
		ver = eregmatch( pattern: "220.*Postfix \\(([0-9\\.]+)\\)", string: banner );
		if(ver[1]){
			version = ver[1];
		}
		set_kb_item( name: "postfix/detected", value: TRUE );
		set_kb_item( name: "postfix/smtp/detected", value: TRUE );
		set_kb_item( name: "postfix/smtp/" + port + "/detected", value: version );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:postfix:postfix:" );
		if(!cpe){
			cpe = "cpe:/a:postfix:postfix";
		}
		register_product( cpe: cpe, location: install, port: port, service: "smtp" );
		log_message( data: build_detection_report( app: "Postfix", version: version, install: install, cpe: cpe, concluded: banner ), port: port );
	}
}
exit( 0 );

