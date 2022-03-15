if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900815" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-08-14 14:09:35 +0200 (Fri, 14 Aug 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "ProFTPD Server Version Detection (Remote)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/proftpd/detected" );
	script_tag( name: "summary", value: "This script detects the installed version of ProFTP Server." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: port );
if(banner && ( ContainsString( banner, "ProFTPD" ) || ContainsString( banner, "NASFTPD Turbo station" ) )){
	ver = "unknown";
	set_kb_item( name: "ProFTPD/Installed", value: TRUE );
	ftpVer = eregmatch( pattern: "(ProFTPD|NASFTPD Turbo station) ([0-9.]+)([A-Za-z0-9]+)?( Server \\(ProFTPD\\))?", string: banner );
	if(ftpVer[2]){
		if( ftpVer[3] ){
			ver = ftpVer[2] + ftpVer[3];
		}
		else {
			ver = ftpVer[2];
		}
		set_kb_item( name: "ProFTPD/" + port + "/Ver", value: ver );
	}
	cpe = build_cpe( value: ftpVer[2], exp: "^([0-9.]+)", base: "cpe:/a:proftpd:proftpd:" );
	if(ftpVer[2] && ftpVer[3] && !isnull( cpe )){
		cpe = cpe + ":" + ftpVer[3];
	}
	if(!cpe){
		cpe = "cpe:/a:proftpd:proftpd";
	}
	register_product( cpe: cpe, location: port + "/tcp", port: port, service: "ftp" );
	log_message( data: build_detection_report( app: "ProFTPD", version: ver, install: port + "/tcp", cpe: cpe, concluded: banner ), port: port );
}
exit( 0 );

