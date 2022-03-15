if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902220" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Cyrus IMAP Server Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "imap4_banner.sc", "popserver_detect.sc" );
	script_require_ports( "Services/imap", 143, 993, "Services/pop3", 110, 995 );
	script_mandatory_keys( "pop3_imap_or_smtp/banner/available" );
	script_tag( name: "summary", value: "This script finds the running version of Cyrus IMAP Server." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("pop3_func.inc.sc");
require("imap_func.inc.sc");
require("host_details.inc.sc");
require("cpe.inc.sc");
require("port_service_func.inc.sc");
ports = imap_get_ports();
for port in ports {
	banner = imap_get_banner( port: port );
	if(!banner){
		continue;
	}
	if(ContainsString( banner, "Cyrus IMAP" ) && ContainsString( banner, "server ready" )){
		version = "unknown";
		install = port + "/tcp";
		vers = eregmatch( pattern: "IMAP4? v?([0-9.]+)", string: banner );
		if(isnull( vers[1] )){
			vers = eregmatch( pattern: "\"version\" \"([0-9.]+)", string: banner );
		}
		if(!isnull( vers[1] )){
			version = vers[1];
		}
		set_kb_item( name: "cyrus/imap_server/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:cyrus:imap:" );
		if(!cpe){
			cpe = "cpe:/a:cyrus:imap";
		}
		register_product( cpe: cpe, location: install, port: port, service: "imap" );
		log_message( data: build_detection_report( app: "Cyrus IMAP Server", version: version, install: install, cpe: cpe, concluded: banner ), port: port );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:cmu:cyrus_imap_server:" );
		if(!cpe){
			cpe = "cpe:/a:cmu:cyrus_imap_server";
		}
		register_product( cpe: cpe, location: install, port: port, service: "imap" );
	}
}
port = pop3_get_port( default: 110 );
banner = pop3_get_banner( port: port );
if(!banner){
	exit( 0 );
}
if(ContainsString( banner, "Cyrus POP3" ) && ContainsString( banner, "server ready" )){
	version = "unknown";
	install = port + "/tcp";
	vers = eregmatch( pattern: "POP3 v([0-9.]+)", string: banner );
	if(!isnull( vers[1] )){
		version = vers[1];
	}
	set_kb_item( name: "cyrus/imap_server/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:cyrus:imap:" );
	if(!cpe){
		cpe = "cpe:/a:cyrus:imap";
	}
	register_product( cpe: cpe, location: install, port: port, service: "pop3" );
	log_message( data: build_detection_report( app: "Cyrus IMAP Server", version: version, install: install, cpe: cpe, concluded: banner ), port: port );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:cmu:cyrus_imap_server:" );
	if(!cpe){
		cpe = "cpe:/a:cmu:cyrus_imap_server";
	}
	register_product( cpe: cpe, location: install, port: port, service: "pop3" );
}
exit( 0 );

