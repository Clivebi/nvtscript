if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111085" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-02-04 15:00:00 +0100 (Thu, 04 Feb 2016)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Microsoft Exchange Server Remote Detection" );
	script_copyright( "Copyright (C) 2016 SCHUTZWERK GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_dependencies( "smtpserver_detect.sc", "popserver_detect.sc", "imap4_banner.sc" );
	script_require_ports( "Services/smtp", 25, 465, 587, "Services/pop3", 110, 995, "Services/imap", 143, 993 );
	script_mandatory_keys( "pop3_imap_or_smtp/banner/available" );
	script_tag( name: "summary", value: "The script checks the SMTP/POP3/IMAP server
  banner for the presence of an Microsoft Exchange Server." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("smtp_func.inc.sc");
require("imap_func.inc.sc");
require("pop3_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
ports = smtp_get_ports();
for port in ports {
	banner = smtp_get_banner( port: port );
	quit = get_kb_item( "smtp/fingerprints/" + port + "/quit_banner" );
	noop = get_kb_item( "smtp/fingerprints/" + port + "/noop_banner" );
	help = get_kb_item( "smtp/fingerprints/" + port + "/help_banner" );
	rset = get_kb_item( "smtp/fingerprints/" + port + "/rset_banner" );
	if(ContainsString( banner, "Microsoft Exchange Internet Mail Service" ) || ContainsString( banner, "NTLM LOGIN" ) || ContainsString( banner, "Microsoft SMTP MAIL" ) || ContainsString( banner, "Microsoft ESMTP MAIL Service" ) || ContainsString( banner, "ESMTP Exchange Server" ) || ContainsString( banner, "ESMTP Microsoft Exchange" ) || ( ( ContainsString( help, "This server supports the following commands" ) || ContainsString( help, "End of HELP information" ) ) && ContainsString( quit, "Service closing transmission channel" ) && ContainsString( rset, "Resetting" ) && ContainsString( noop, "OK" ) )){
		version = "unknown";
		install = port + "/tcp";
		ver = eregmatch( pattern: "Version: ([0-9.]+)", string: banner );
		if(ver[1]){
			version = ver[1];
		}
		if(version == "unknown"){
			ver = eregmatch( pattern: "Service ([0-9.]+)", string: banner );
			if(ver[1]){
				version = ver[1];
			}
		}
		if(version == "unknown"){
			ver = eregmatch( pattern: "Microsoft Exchange Server .* ([0-9.]+)", string: banner );
			if(ver[1]){
				version = ver[1];
			}
		}
		set_kb_item( name: "microsoft/exchange_server/smtp/detected", value: TRUE );
		set_kb_item( name: "microsoft/exchange_server/smtp/" + port + "/detected", value: TRUE );
		set_kb_item( name: "microsoft/exchange_server/detected", value: TRUE );
		cpe = "cpe:/a:microsoft:exchange_server";
		register_product( cpe: cpe, location: install, port: port, service: "smtp" );
		log_message( data: build_detection_report( app: "Microsoft Exchange", install: install, cpe: cpe, extra: "Service version: " + version, concluded: banner ), port: port );
	}
}
ports = imap_get_ports();
for port in ports {
	banner = imap_get_banner( port: port );
	if(ContainsString( banner, "The Microsoft Exchange IMAP4 service is ready" ) || ContainsString( banner, "Microsoft Exchange Server" )){
		version = "unknown";
		install = port + "/tcp";
		ver = eregmatch( pattern: "Version ([0-9.]+)", string: banner );
		if(ver[1]){
			version = ver[1];
		}
		if(version == "unknown"){
			ver = eregmatch( pattern: "Microsoft Exchange Server .* ([0-9.]+)", string: banner );
			if(ver[1]){
				version = ver[1];
			}
		}
		set_kb_item( name: "microsoft/exchange_server/imap/detected", value: TRUE );
		set_kb_item( name: "microsoft/exchange_server/imap/" + port + "/detected", value: TRUE );
		set_kb_item( name: "microsoft/exchange_server/detected", value: TRUE );
		cpe = "cpe:/a:microsoft:exchange_server";
		register_product( cpe: cpe, location: install, port: port, service: "imap" );
		log_message( data: build_detection_report( app: "Microsoft Exchange", install: install, cpe: cpe, extra: "Service version: " + version, concluded: banner ), port: port );
	}
}
port = pop3_get_port( default: 110 );
banner = pop3_get_banner( port: port );
if(ContainsString( banner, "Microsoft Windows POP3 Service Version" ) || ContainsString( banner, "The Microsoft Exchange POP3 service is ready." ) || ContainsString( banner, "Microsoft Exchange Server" ) || ContainsString( banner, "Microsoft Exchange POP3-Server" )){
	version = "unknown";
	install = port + "/tcp";
	ver = eregmatch( pattern: "Version ([0-9.]+)", string: banner );
	if(ver[1]){
		version = ver[1];
	}
	if(version == "unknown"){
		ver = eregmatch( pattern: "Microsoft Exchange Server .* ([0-9.]+)", string: banner );
		if(ver[1]){
			version = ver[1];
		}
	}
	set_kb_item( name: "microsoft/exchange_server/pop3/detected", value: TRUE );
	set_kb_item( name: "microsoft/exchange_server/pop3/" + port + "/detected", value: TRUE );
	set_kb_item( name: "microsoft/exchange_server/detected", value: TRUE );
	cpe = "cpe:/a:microsoft:exchange_server";
	register_product( cpe: cpe, location: install, port: port, service: "pop3" );
	log_message( data: build_detection_report( app: "Microsoft Exchange", install: install, cpe: cpe, extra: "Service version: " + version, concluded: banner ), port: port );
}
exit( 0 );

