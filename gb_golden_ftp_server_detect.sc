if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801072" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-12-05 12:49:16 +0100 (Sat, 05 Dec 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Golden FTP Server Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/golden_tfp/detected" );
	script_tag( name: "summary", value: "Detection of Golden FTP Server.

  This script determines Golden FTP server version on the remote host." );
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
if(( ContainsString( banner, "Golden FTP Server" ) ) && ( !ContainsString( banner, "Pro" ) )){
	version = "unknown";
	gfftpVer = eregmatch( pattern: "v([0-9.]+)", string: banner );
	if(!isnull( gfftpVer[1] )){
		version = gfftpVer[1];
		set_kb_item( name: "Golden/FTP/Free/Ver", value: version );
	}
	set_kb_item( name: "Golden/FTP/Free_or_Pro/installed", value: TRUE );
	set_kb_item( name: "Golden/FTP/Free/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:kmint21:golden_ftp_server:" );
	if(!cpe){
		cpe = "cpe:/a:kmint21:golden_ftp_server";
	}
	register_product( cpe: cpe, location: port + "/tcp", port: port, service: "ftp" );
	log_message( data: build_detection_report( app: "Golden FTP Free", version: version, install: port + "/tcp", cpe: cpe, concluded: banner ), port: port );
	exit( 0 );
}
if(ContainsString( banner, "Golden FTP Server Pro" )){
	version = "unknown";
	gftpVer = eregmatch( pattern: "v([0-9.]+)", string: banner );
	if(!isnull( gftpVer[1] )){
		version = gftpVer[1];
		set_kb_item( name: "Golden/FTP/Pro/Ver", value: version );
	}
	set_kb_item( name: "Golden/FTP/Free_or_Pro/installed", value: TRUE );
	set_kb_item( name: "Golden/FTP/Pro/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:kmint21:golden_ftp_server:" );
	if(!cpe){
		cpe = "cpe:/a:kmint21:golden_ftp_server";
	}
	register_product( cpe: cpe, location: port + "/tcp", port: port, service: "ftp" );
	log_message( data: build_detection_report( app: "Golden FTP Pro", version: version, install: port + "/tcp", cpe: cpe, concluded: banner ), port: port );
}
exit( 0 );

