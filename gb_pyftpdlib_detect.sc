if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801612" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-10-28 11:50:37 +0200 (Thu, 28 Oct 2010)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "pyftpdlib Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/pyftpdlib/detected" );
	script_tag( name: "summary", value: "Detection of pyftpdlib

  This script finds the version of running FTPServer.py in pyftpdlib." );
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
if(banner && ContainsString( tolower( banner ), "pyftpd" )){
	version = "unknown";
	ver = eregmatch( pattern: "(Pyftpd|pyftpdlib) ([0-9.]+)", string: banner, icase: TRUE );
	if(!isnull( ver[2] )){
		version = ver[2];
		set_kb_item( name: "pyftpdlib/Ver", value: version );
	}
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:g.rodola:pyftpdlib:" );
	if(!cpe){
		cpe = "cpe:/a:g.rodola:pyftpdlib";
	}
	register_product( cpe: cpe, location: port + "/tcp", port: port, service: "ftp" );
	log_message( data: build_detection_report( app: "pyftpdlib FTP Server", version: version, install: port + "/tcp", cpe: cpe, concluded: banner ), port: port );
}
exit( 0 );

