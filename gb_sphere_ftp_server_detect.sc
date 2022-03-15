if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807533" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-04-04 16:23:30 +0530 (Mon, 04 Apr 2016)" );
	script_name( "SphereFTP Server Remote Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/menasoft/sphereftp/detected" );
	script_tag( name: "summary", value: "Detects the installed version of
  SphereFTP Server.

  The script sends a connection request to the server and attempts to
  extract the version from the reply" );
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
if(banner && ContainsString( banner, "Menasoft GrayFTP Server" )){
	version = "unknown";
	sphVer = eregmatch( pattern: "Menasoft GrayFTP Server \\(v([0-9.]+)\\)", string: banner );
	if(sphVer[1]){
		version = sphVer[1];
		set_kb_item( name: "SphereFTP/Server/Ver", value: version );
	}
	set_kb_item( name: "SphereFTP Server/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "([0-9.]+)", base: "cpe:/a:menasoft:sphereftpserver:" );
	if(isnull( cpe )){
		cpe = "cpe:/a:menasoft:sphereftpserver";
	}
	register_product( cpe: cpe, location: "/", port: ftpPort, service: "ftp" );
	log_message( data: build_detection_report( app: "SphereFTP Server", version: version, install: "/", cpe: cpe, concluded: banner ), port: ftpPort );
}
exit( 0 );

