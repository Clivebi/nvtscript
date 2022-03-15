if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900518" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-03-23 08:26:42 +0100 (Mon, 23 Mar 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "FileZilla Server Detection (FTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/filezilla/detected" );
	script_tag( name: "summary", value: "FTP based detection of a FileZilla Server." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: port );
if(ContainsString( banner, "FileZilla Server" )){
	version = "unknown";
	install = port + "/tcp";
	vers = eregmatch( pattern: "FileZilla Server (version )?([0-9a-z.]+)", string: banner );
	if(!isnull( vers[2] )){
		version = vers[2];
		set_kb_item( name: "FileZilla/Serv/Ver", value: version );
	}
	set_kb_item( name: "FileZilla/Serv/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+([a-z])?)", base: "cpe:/a:filezilla:filezilla_server:" );
	if(!cpe){
		cpe = "cpe:/a:filezilla:filezilla_server";
	}
	register_product( cpe: cpe, location: install, port: port, service: "ftp" );
	log_message( data: build_detection_report( app: "FileZilla Server", version: version, install: install, cpe: cpe, concluded: banner ), port: port );
}
exit( 0 );

