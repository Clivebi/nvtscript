if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801119" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-10-22 15:34:45 +0200 (Thu, 22 Oct 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "XM Easy Personal FTP Server Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/xm_easy_personal/detected" );
	script_tag( name: "summary", value: "Detection of XM Easy Personal FTP Server.

  This script detects the installed version of XM Easy Personal FTP Server." );
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
if(banner && ContainsString( banner, "Welcome to DXM's FTP Server" )){
	version = "unknown";
	xmVer = eregmatch( pattern: "DXM's FTP Server ([0-9.]+)", string: banner );
	if(!isnull( xmVer[1] )){
		version = xmVer[1];
		set_kb_item( name: "XM-Easy-Personal-FTP/Ver", value: version );
	}
	set_kb_item( name: "XM-Easy-Personal-FTP/installed", value: TRUE );
	cpe = build_cpe( value: xmVer[1], exp: "^([0-9.]+)", base: "cpe:/a:dxmsoft:xm_easy_personal_ftp_server:" );
	if(!cpe){
		cpe = "cpe:/a:dxmsoft:xm_easy_personal_ftp_server";
	}
	register_product( cpe: cpe, location: port + "/tcp", port: port, service: "ftp" );
	log_message( data: build_detection_report( app: "XM Easy Personl FTP Server", version: version, install: port + "/tcp", cpe: cpe, concluded: banner ), port: port );
}
exit( 0 );

