if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111050" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-11-11 18:00:00 +0100 (Wed, 11 Nov 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "vsFTPd FTP Server Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_family( "Product detection" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/vsftpd/detected" );
	script_tag( name: "summary", value: "The script is grabbing the
  banner of a FTP server and attempts to identify a vsFTPd FTP Server
  and its version from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("cpe.inc.sc");
port = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: port );
if(!banner || !ContainsString( tolower( banner ), "vsftpd" )){
	exit( 0 );
}
vers = "unknown";
version = eregmatch( pattern: "vsftpd ([0-9.]+)", string: tolower( banner ) );
if(!isnull( version[1] )){
	vers = version[1];
	set_kb_item( name: "ftp/" + port + "/vsftpd", value: vers );
}
set_kb_item( name: "vsftpd/installed", value: TRUE );
cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:beasts:vsftpd:" );
if(isnull( cpe )){
	cpe = "cpe:/a:beasts:vsftpd";
}
register_product( cpe: cpe, location: port + "/tcp", port: port, service: "ftp" );
log_message( data: build_detection_report( app: "vsFTPd", version: vers, install: port + "/tcp", cpe: cpe, concluded: banner ), port: port );
exit( 0 );

