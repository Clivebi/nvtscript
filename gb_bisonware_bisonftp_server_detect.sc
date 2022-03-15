if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805752" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-09-28 17:53:15 +0530 (Mon, 28 Sep 2015)" );
	script_name( "BisonWare BisonFTP Server Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/bisonware/bisonftp/detected" );
	script_tag( name: "summary", value: "This script detects the installed
  version of BisonWare BisonFTP Server." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
ftpPort = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: ftpPort );
if(banner && ContainsString( banner, "BisonWare BisonFTP server" )){
	ftpVer = "unknown";
	ver = eregmatch( pattern: "product V([0-9.]+)", string: banner );
	if(ver[1]){
		ftpVer = ver[1];
	}
	set_kb_item( name: "BisonWare/Ftp/Installed", value: TRUE );
	cpe = build_cpe( value: ftpVer, exp: "^([0-9.]+)", base: "cpe:/a:bisonware:bison_ftp_server:" );
	if(!cpe){
		cpe = "cpe:/a:bisonware:bison_ftp_server";
	}
	register_product( cpe: cpe, location: ftpPort + "/tcp", port: ftpPort, service: "ftp" );
	log_message( data: build_detection_report( app: "BisonWare BisonFTP Server", version: ftpVer, install: ftpPort + "/tcp", cpe: cpe, concluded: banner ), port: ftpPort );
}
exit( 0 );

