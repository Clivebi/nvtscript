if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111110" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-07-12 17:00:00 +0200 (Tue, 12 Jul 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Pure-FTPd FTP Server Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 SCHUTZWERK GmbH" );
	script_family( "Product detection" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/pure_ftpd/detected" );
	script_tag( name: "summary", value: "The script is grabbing the banner of a FTP server
  and sends a 'HELP' command to identify a Pure-FTPd FTP Server from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://www.pureftpd.org" );
	exit( 0 );
}
require("cpe.inc.sc");
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: port );
command = ftp_get_cmd_banner( port: port, cmd: "HELP" );
if( ContainsString( banner, "Welcome to Pure-FTPd" ) || ContainsString( banner, "Welcome to PureFTPd" ) ){
	installed = TRUE;
	concluded = banner;
}
else {
	if(ContainsString( command, "Pure-FTPd - http://pureftpd.org" )){
		installed = TRUE;
		concluded = command;
	}
}
if(installed){
	install = port + "/tcp";
	version = "unknown";
	ver = eregmatch( pattern: "Welcome to Pure[-]?FTPd ([0-9.]+)", string: banner );
	if(!isnull( ver[1] )){
		version = ver[1];
		concluded = ver[0];
	}
	set_kb_item( name: "pure-ftpd/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:pureftpd:pure-ftpd:" );
	if(!cpe){
		cpe = "cpe:/a:pureftpd:pure-ftpd";
	}
	register_product( cpe: cpe, location: install, port: port, service: "ftp" );
	log_message( data: build_detection_report( app: "Pure-FTPd", version: version, install: install, cpe: cpe, concluded: concluded ), port: port );
}
exit( 0 );

