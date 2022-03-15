if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108749" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-04-17 07:43:42 +0000 (Fri, 17 Apr 2020)" );
	script_name( "DrayTek Vigor Detection (FTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/draytek/detected" );
	script_tag( name: "summary", value: "Detection of DrayTek Vigor devices via FTP.

  The script attempts to identify a DrayTek Vigor device via a FTP banner." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: port );
if(!banner || !ContainsString( banner, "220 DrayTek FTP" )){
	exit( 0 );
}
version = "unknown";
set_kb_item( name: "draytek/vigor/detected", value: TRUE );
set_kb_item( name: "draytek/vigor/ftp/detected", value: TRUE );
set_kb_item( name: "draytek/vigor/ftp/port", value: port );
set_kb_item( name: "draytek/vigor/ftp/" + port + "/concluded", value: banner );
set_kb_item( name: "draytek/vigor/ftp/" + port + "/version", value: version );
exit( 0 );

