if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900917" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-08-20 09:27:17 +0200 (Thu, 20 Aug 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "CMailServer Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smtpserver_detect.sc", "imap4_banner.sc", "popserver_detect.sc" );
	script_require_ports( "Services/smtp", 25, 465, 587, "Services/imap", 143, 993, "Services/pop3", 110, 995 );
	script_mandatory_keys( "pop3_imap_or_smtp/banner/available" );
	script_tag( name: "summary", value: "The script detects the installed version of a CMailServer." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("smtp_func.inc.sc");
require("imap_func.inc.sc");
require("pop3_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
smtpPorts = smtp_get_ports();
for port in smtpPorts {
	banner = smtp_get_banner( port: port );
	if(banner && ContainsString( banner, "CMailServer" )){
		set_kb_item( name: "CMailServer/Installed", value: TRUE );
		ver = eregmatch( pattern: "CMailServer ([0-9.]+)", string: banner );
		version = "unknown";
		if(ver[1]){
			version = ver[1];
			set_kb_item( name: "CMailServer/Ver", value: version );
		}
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:youngzsoft:cmailserver:" );
		if(!cpe){
			cpe = "cpe:/a:youngzsoft:cmailserver";
		}
		register_product( cpe: cpe, location: "/", port: port, service: "smtp" );
		log_message( data: build_detection_report( app: "Youngzsoft CMailServer", version: version, install: "/", cpe: cpe, concluded: ver[0] ), port: port );
	}
}
imapPorts = imap_get_ports();
for port in imapPorts {
	banner = imap_get_banner( port: port );
	if(banner && ContainsString( banner, "CMailServer" )){
		set_kb_item( name: "CMailServer/Installed", value: TRUE );
		ver = eregmatch( pattern: "CMailServer ([0-9.]+)", string: banner );
		version = "unknown";
		if(ver[1]){
			version = ver[1];
			set_kb_item( name: "CMailServer/Ver", value: version );
		}
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:youngzsoft:cmailserver:" );
		if(!cpe){
			cpe = "cpe:/a:youngzsoft:cmailserver";
		}
		register_product( cpe: cpe, location: "/", port: port, service: "imap" );
		log_message( data: build_detection_report( app: "Youngzsoft CMailServer", version: version, install: "/", cpe: cpe, concluded: ver[0] ), port: port );
	}
}
popPorts = pop3_get_ports();
for port in popPorts {
	banner = pop3_get_banner( port: port );
	if(banner && ContainsString( banner, "CMailServer" )){
		set_kb_item( name: "CMailServer/Installed", value: TRUE );
		ver = eregmatch( pattern: "CMailServer ([0-9.]+)", string: banner );
		version = "unknown";
		if(ver[1]){
			version = ver[1];
			set_kb_item( name: "CMailServer/Ver", value: version );
		}
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:youngzsoft:cmailserver:" );
		if(!cpe){
			cpe = "cpe:/a:youngzsoft:cmailserver";
		}
		register_product( cpe: cpe, location: "/", port: port, service: "pop3" );
		log_message( data: build_detection_report( app: "Youngzsoft CMailServer", version: version, install: "/", cpe: cpe, concluded: ver[0] ), port: port );
	}
}
exit( 0 );

