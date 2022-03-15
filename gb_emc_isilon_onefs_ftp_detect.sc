if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106553" );
	script_version( "2021-04-22T08:43:12+0000" );
	script_tag( name: "last_modification", value: "2021-04-22 08:43:12 +0000 (Thu, 22 Apr 2021)" );
	script_tag( name: "creation_date", value: "2017-01-30 15:26:27 +0700 (Mon, 30 Jan 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Dell EMC PowerScale OneFS (Isilion OneFS) Detection (FTP)" );
	script_tag( name: "summary", value: "FTP based detection of Dell EMC PowerScale OneFS (formerly
  Isilion OneFS)." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/emc/isilon_onefs/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: port );
if(!banner || !ContainsString( banner, "Isilon OneFS" )){
	exit( 0 );
}
version = "unknown";
set_kb_item( name: "dell/emc_isilon/onefs/detected", value: TRUE );
set_kb_item( name: "dell/emc_isilon/onefs/ftp/port", value: port );
set_kb_item( name: "dell/emc_isilon/onefs/ftp/" + port + "/concluded", value: banner );
vers = eregmatch( pattern: "Isilon OneFS v([0-9.]+)", string: banner );
if(!isnull( vers[1] )){
	version = vers[1];
}
set_kb_item( name: "dell/emc_isilon/onefs/ftp/" + port + "/version", value: version );
exit( 0 );

