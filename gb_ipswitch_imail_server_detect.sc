if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811256" );
	script_version( "2020-08-25T06:34:32+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-25 06:34:32 +0000 (Tue, 25 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-07-26 16:06:50 +0530 (Wed, 26 Jul 2017)" );
	script_name( "Ipswitch IMail Server Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smtpserver_detect.sc", "popserver_detect.sc", "imap4_banner.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/smtp", 25, 465, 587, "Services/pop3", 110, 995, "Services/imap", 143, 993, "Services/www", 80 );
	script_tag( name: "summary", value: "Detection of installed version
  of Ipswitch IMail Server.

  This script check the presence of Ipswitch IMail Server from the
  banner." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("smtp_func.inc.sc");
require("pop3_func.inc.sc");
require("imap_func.inc.sc");
require("misc_func.inc.sc");
func get_ipswitch_version( banner, port, service ){
	set_kb_item( name: "Ipswitch/IMail/detected", value: TRUE );
	version = "unknown";
	install = port + "/tcp";
	mailVer = eregmatch( pattern: "Server: Ipswitch-IMail/([0-9.]+)", string: banner );
	if(!mailVer){
		mailVer = eregmatch( pattern: "IMail ([0-9.]+)", string: banner );
	}
	if(mailVer[1]){
		version = mailVer[1];
	}
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:ipswitch:imail_server:" );
	if(!cpe){
		cpe = "cpe:/a:ipswitch:imail_server";
	}
	register_product( cpe: cpe, location: install, port: port, service: service );
	log_message( data: build_detection_report( app: "Ipswitch IMail Server", version: version, install: install, cpe: cpe, concluded: mailVer[0] ), port: port );
}
ports = pop3_get_ports();
for port in ports {
	if(banner = pop3_get_banner( port: port )){
		if(ContainsString( banner, "POP3 Server" ) && ContainsString( banner, "(IMail" )){
			get_ipswitch_version( banner: banner, port: port, service: "pop3" );
		}
	}
}
ports = smtp_get_ports();
for port in ports {
	if(banner = smtp_get_banner( port: port )){
		if(ContainsString( banner, "ESMTP Server" ) && ContainsString( banner, "(IMail" )){
			get_ipswitch_version( banner: banner, port: port, service: "smtp" );
		}
	}
}
ports = imap_get_ports();
for port in ports {
	if(banner = imap_get_banner( port: port )){
		if(ContainsString( banner, "IMAP4 Server" ) && ContainsString( banner, "(IMail" )){
			get_ipswitch_version( banner: banner, port: port, service: "imap" );
		}
	}
}
if(http_is_cgi_scan_disabled()){
	exit( 0 );
}
port = http_get_port( default: 80 );
if(banner = http_get_remote_headers( port: port )){
	if(ContainsString( banner, "Server: Ipswitch-IMail" )){
		get_ipswitch_version( banner: banner, port: port, service: "www" );
	}
}
exit( 0 );

