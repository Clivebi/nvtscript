if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142809" );
	script_version( "2021-09-10T12:50:44+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 12:50:44 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-08-28 04:15:03 +0000 (Wed, 28 Aug 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "RICOH Printer Detection (FTP)" );
	script_tag( name: "summary", value: "FTP based detection of RICOH printer devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/ricoh/printer/detected" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: port );
if(banner && ContainsString( banner, "RICOH" ) && ContainsString( banner, "FTP server" )){
	version = "unknown";
	model = "unknown";
	set_kb_item( name: "ricoh/printer/detected", value: TRUE );
	set_kb_item( name: "ricoh/printer/ftp/detected", value: TRUE );
	set_kb_item( name: "ricoh/printer/ftp/port", value: port );
	set_kb_item( name: "ricoh/printer/ftp/" + port + "/concluded", value: banner );
	mod = eregmatch( pattern: "RICOH ((Aficio |Pro)?([A-Z]+)? [^ ]+)", string: banner );
	if(!isnull( mod[1] )){
		model = mod[1];
	}
	set_kb_item( name: "ricoh/printer/ftp/" + port + "/model", value: model );
	set_kb_item( name: "ricoh/printer/ftp/" + port + "/fw_version", value: version );
}
exit( 0 );

