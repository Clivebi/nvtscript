if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800236" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-02-11 16:51:00 +0100 (Wed, 11 Feb 2009)" );
	script_name( "Titan FTP Server Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/titan/ftp/detected" );
	script_tag( name: "summary", value: "Detection of Titan FTP Server

  The script sends a connection request to the server and attempts to extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: port );
if(banner && ContainsString( banner, "220 Titan FTP Server " )){
	version = "unknown";
	install = port + "/tcp";
	titanVer = eregmatch( pattern: "Titan FTP Server ([0-9.]+)", string: banner );
	if(!isnull( titanVer[1] )){
		version = titanVer[1];
	}
	set_kb_item( name: "TitanFTP/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:southrivertech:titan_ftp_server:" );
	if(!cpe){
		cpe = "cpe:/a:southrivertech:titan_ftp_server";
	}
	register_product( cpe: cpe, location: install, port: port, service: "ftp" );
	log_message( data: build_detection_report( app: "Titan FTP Server", version: version, install: install, cpe: cpe, concluded: banner ), port: port );
}
exit( 0 );

