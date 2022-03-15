if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901005" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-08-27 13:43:20 +0200 (Thu, 27 Aug 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "tnftpd Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/tnftpd/detected" );
	script_tag( name: "summary", value: "Detection of tnftpd.

  This script finds the running tnftpd Version." );
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
if(banner && ContainsString( banner, "tnftpd" )){
	version = "unknown";
	ntftpVer = eregmatch( pattern: "tnftpd ([0-9]+)", string: banner );
	if(!isnull( ntftpVer[1] )){
		version = ntftpVer[1];
		set_kb_item( name: "tnftpd/Ver", value: version );
	}
	set_kb_item( name: "tnftpd/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:luke_mewburn:tnftpd:" );
	if(!cpe){
		cpe = "cpe:/a:luke_mewburn:tnftpd";
	}
	register_product( cpe: cpe, location: port + "/tcp", port: port, service: "ftp" );
	log_message( data: build_detection_report( app: "tnftpd", version: version, install: port + "/tcp", cpe: cpe, concluded: banner ), port: port );
}
exit( 0 );

