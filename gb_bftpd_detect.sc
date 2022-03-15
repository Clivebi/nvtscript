if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140514" );
	script_version( "2021-08-31T13:35:08+0000" );
	script_tag( name: "last_modification", value: "2021-08-31 13:35:08 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "creation_date", value: "2017-11-21 10:02:35 +0700 (Tue, 21 Nov 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Bftpd FTP Server Detection (FTP)" );
	script_tag( name: "summary", value: "FTP based detection of Bftpd FTP Server." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/bftpd/detected" );
	script_xref( name: "URL", value: "http://bftpd.sourceforge.net/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: port );
if(banner && IsMatchRegexp( banner, "^220 bftpd " )){
	version = "unknown";
	vers = eregmatch( pattern: "bftpd ([0-9.]+)", string: banner );
	if(!isnull( vers[1] )){
		version = vers[1];
	}
	set_kb_item( name: "bftpd/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:bftpd:bftpd:" );
	if(!cpe){
		cpe = "cpe:/a:bftpd:bftpd";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "ftp" );
	log_message( data: build_detection_report( app: "Bftpd", version: version, install: "/", cpe: cpe, concluded: banner ), port: port );
}
exit( 0 );

