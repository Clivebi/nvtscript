if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105189" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:40:14+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:40:14 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-01-29 15:29:06 +0100 (Thu, 29 Jan 2015)" );
	script_name( "Exim Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "smtpserver_detect.sc" );
	script_mandatory_keys( "smtp/banner/available" );
	script_tag( name: "summary", value: "The script sends a connection request to the
  server and attempts to extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("smtp_func.inc.sc");
require("host_details.inc.sc");
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
	if(ContainsString( banner, "ESMTP Exim" ) || ( ContainsString( quit, "closing connection" ) && ContainsString( noop, "OK" ) && ContainsString( help, "Commands supported:" ) && ContainsString( rset, "Reset OK" ) )){
		vers = "unknown";
		install = port + "/tcp";
		version = eregmatch( pattern: "ESMTP Exim ([0-9.]+(_[0-9]+)?)", string: banner );
		if(version[1]){
			vers = version[1];
		}
		if(ContainsString( vers, "_" )){
			vers = str_replace( string: vers, find: "_", replace: "." );
		}
		set_kb_item( name: "exim/installed", value: TRUE );
		set_kb_item( name: "smtp/" + port + "/exim", value: vers );
		cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:exim:exim:" );
		if(!cpe){
			cpe = "cpe:/a:exim:exim";
		}
		register_product( cpe: cpe, location: install, port: port, service: "smtp" );
		log_message( data: build_detection_report( app: "Exim", version: vers, install: install, cpe: cpe, concluded: banner ), port: port );
	}
}
exit( 0 );

