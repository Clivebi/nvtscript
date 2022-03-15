if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146408" );
	script_version( "2021-07-30T10:14:55+0000" );
	script_tag( name: "last_modification", value: "2021-07-30 10:14:55 +0000 (Fri, 30 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-30 09:54:37 +0000 (Fri, 30 Jul 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Epson Printer Detection (FTP)" );
	script_tag( name: "summary", value: "FTP based detection of Epson printer devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/epson/printer/detected" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: port );
if(banner && ContainsString( banner, " FTP server " ) && ContainsString( banner, "(OEM FTPD version" )){
	model = "unknown";
	fw_version = "unknown";
	hw_version = "unknown";
	set_kb_item( name: "epson/printer/detected", value: TRUE );
	set_kb_item( name: "epson/printer/ftp/detected", value: TRUE );
	set_kb_item( name: "epson/printer/ftp/port", value: port );
	set_kb_item( name: "epson/printer/ftp/" + port + "/concluded", value: banner );
	mod = eregmatch( pattern: "^220 ([^ ]+)", string: banner );
	if(!isnull( mod[1] )){
		mod = split( buffer: mod[1], sep: "-", keep: FALSE );
		if( max_index( mod ) > 1 ) {
			model = mod[0] + "-" + mod[1];
		}
		else {
			model = mod[0];
		}
	}
	set_kb_item( name: "epson/printer/ftp/" + port + "/model", value: model );
	set_kb_item( name: "epson/printer/ftp/" + port + "/fw_version", value: fw_version );
	set_kb_item( name: "epson/printer/ftp/" + port + "/hw_version", value: hw_version );
}
exit( 0 );

