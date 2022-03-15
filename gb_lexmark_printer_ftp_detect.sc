if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142836" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-09-03 01:48:49 +0000 (Tue, 03 Sep 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Lexmark Printer Detection (FTP)" );
	script_tag( name: "summary", value: "This script performs FTP based detection of Lexmark printer devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/lexmark/printer/detected" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: port );
if(banner && ContainsString( banner, "Lexmark" ) && ContainsString( banner, "FTP Server" )){
	set_kb_item( name: "lexmark_printer/detected", value: TRUE );
	set_kb_item( name: "lexmark_printer/ftp/detected", value: TRUE );
	set_kb_item( name: "lexmark_printer/ftp/port", value: port );
	set_kb_item( name: "lexmark_printer/ftp/" + port + "/concluded", value: banner );
	model = eregmatch( pattern: "Lexmark ([^ ]+)", string: banner );
	if(!isnull( model[1] )){
		set_kb_item( name: "lexmark_printer/ftp/" + port + "/model", value: model[1] );
	}
	version = eregmatch( pattern: "FTP Server ([^ ]+) ready", string: banner );
	if(!isnull( version[1] ) && !IsMatchRegexp( version[1], "^N" )){
		set_kb_item( name: "lexmark_printer/ftp/" + port + "/fw_version", value: version[1] );
	}
}
exit( 0 );

