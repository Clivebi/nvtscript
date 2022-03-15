if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100131" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-04-13 18:06:40 +0200 (Mon, 13 Apr 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Ftpdmin Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/ftpdmin/detected" );
	script_xref( name: "URL", value: "http://www.sentex.net/~mwandel/ftpdmin/" );
	script_tag( name: "summary", value: "Detection of Ftpdmin.

  Ftpdmin is running at this port. Ftpdmin is a minimal Windows FTP server." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("ftp_func.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: port );
if(banner && ContainsString( banner, "Minftpd" )){
	vers = "unknown";
	syst = ftp_get_cmd_banner( port: port, cmd: "SYST" );
	version = eregmatch( pattern: "^215.*ftpdmin v\\. ([0-9.]+)", string: syst );
	if(!isnull( version[1] )){
		vers = version[1];
	}
	set_kb_item( name: "ftpdmin/Ver", value: vers );
	set_kb_item( name: "ftpdmin/installed", value: TRUE );
	cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:ftpdmin:ftpdmin:" );
	if(!cpe){
		cpe = "cpe:/a:ftpdmin:ftpdmin";
	}
	register_product( cpe: cpe, location: port + "/tcp", port: port, service: "ftp" );
	log_message( data: build_detection_report( app: "Ftpdmin", version: vers, install: port + "/tcp", cpe: cpe, concluded: version[0] ), port: port );
}
exit( 0 );

