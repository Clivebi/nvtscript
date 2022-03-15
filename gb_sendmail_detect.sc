if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800608" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-05-13 10:01:19 +0200 (Wed, 13 May 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Sendmail / Sendmail Switch / SMI Sendmail Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smtpserver_detect.sc" );
	script_require_ports( "Services/smtp", 25, 465, 587 );
	script_mandatory_keys( "smtp/banner/available" );
	script_tag( name: "summary", value: "The script tries to detect an installed Sendmail / Sendmail Switch
  / SMI Sendmail SMTP server." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("smtp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = smtp_get_port( default: 25 );
banner = smtp_get_banner( port: port );
quit = get_kb_item( "smtp/fingerprints/" + port + "/quit_banner" );
noop = get_kb_item( "smtp/fingerprints/" + port + "/noop_banner" );
help = get_kb_item( "smtp/fingerprints/" + port + "/help_banner" );
rset = get_kb_item( "smtp/fingerprints/" + port + "/rset_banner" );
if(ContainsString( banner, "Sendmail" ) || ContainsString( banner, "220 smtp sendmail" ) || ( ( ContainsString( help, "This is sendmail version" ) || ContainsString( help, "sendmail-bugs@sendmail.org" ) || ContainsString( help, "HELP not implemented" ) || ContainsString( help, "Syntax Error, command unrecognized" ) ) && ContainsString( noop, "OK" ) && ( ContainsString( rset, "Reset state" ) || ContainsString( rset, "OK" ) ) && ( ContainsString( quit, "closing connection" ) || ContainsString( quit, "Closing connection" ) ) )){
	version = "unknown";
	install = port + "/tcp";
	if( IsMatchRegexp( banner, "Sendmail.+/Switch-" ) ){
		app = "Sendmail Switch";
		base_cpe = "cpe:/a:sendmail:sendmail_switch";
		vers = eregmatch( pattern: "Sendmail.+/Switch-([0-9.]+)", string: banner );
		if(vers[1]){
			version = vers[1];
		}
		set_kb_item( name: "sendmail_switch/detected", value: TRUE );
		set_kb_item( name: "sendmail_switch/" + port + "/version", value: version );
		set_kb_item( name: "sendmail_switch/" + port + "/detected", value: TRUE );
	}
	else {
		if( IsMatchRegexp( banner, "Sendmail.+/SMI-" ) ){
			app = "SMI Sendmail";
			base_cpe = "cpe:/a:sun:smi_sendmail";
			vers = eregmatch( pattern: "Sendmail.+/SMI-([0-9.]+)", string: banner );
			if(vers[1]){
				version = vers[1];
			}
			set_kb_item( name: "smi_sendmail/detected", value: TRUE );
			set_kb_item( name: "smi_sendmail/" + port + "/version", value: version );
			set_kb_item( name: "smi_sendmail/" + port + "/detected", value: TRUE );
		}
		else {
			if( IsMatchRegexp( banner, "Sendmail.+/UCB " ) ){
				app = "Sendmail UCB";
				base_cpe = "cpe:/a:sendmail:sendmail_ucb";
				vers = eregmatch( pattern: "Sendmail.+/UCB ([0-9.]+)", string: banner );
				if(vers[1]){
					version = vers[1];
				}
				set_kb_item( name: "sendmail_ucb/detected", value: TRUE );
				set_kb_item( name: "sendmail_ucb/" + port + "/version", value: version );
				set_kb_item( name: "sendmail_ucb/" + port + "/detected", value: TRUE );
			}
			else {
				app = "Sendmail";
				base_cpe = "cpe:/a:sendmail:sendmail";
				vers = eregmatch( pattern: "ESMTP Sendmail ([0-9.]+)", string: banner );
				if(vers[1]){
					version = vers[1];
				}
				if(version == "unknown"){
					vers = eregmatch( pattern: "This is sendmail version ([0-9.]+)", string: help );
					if(vers[1]){
						version = vers[1];
					}
				}
				if(version == "unknown"){
					vers = eregmatch( pattern: "Sendmail ([0-9.]+)", string: help );
					if(vers[1]){
						version = vers[1];
					}
				}
				if(version == "unknown"){
					vers = eregmatch( pattern: "smtp sendmail v([0-9.]+)", string: banner );
					if(vers[1]){
						version = vers[1];
					}
				}
				set_kb_item( name: "sendmail/detected", value: TRUE );
				set_kb_item( name: "sendmail/" + port + "/version", value: version );
				set_kb_item( name: "sendmail/" + port + "/detected", value: TRUE );
			}
		}
	}
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: base_cpe + ":" );
	if(isnull( cpe )){
		cpe = base_cpe;
	}
	register_product( cpe: cpe, location: install, port: port, service: "smtp" );
	log_message( data: build_detection_report( app: app, version: version, install: install, cpe: cpe, concluded: vers[0] ), port: port );
}
exit( 0 );

