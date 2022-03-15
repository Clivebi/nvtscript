CPE = "cpe:/a:mongodb:mongodb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105235" );
	script_version( "2020-02-10T09:45:14+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-02-10 09:45:14 +0000 (Mon, 10 Feb 2020)" );
	script_tag( name: "creation_date", value: "2015-03-13 09:16:37 +0100 (Fri, 13 Mar 2015)" );
	script_name( "Unprotected MongoDB Service" );
	script_category( ACT_ATTACK );
	script_family( "Databases" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_mongodb_detect.sc" );
	script_require_ports( "Services/mongodb", 27017 );
	script_mandatory_keys( "mongodb/installed" );
	script_tag( name: "impact", value: "Attackers can exploit this issue to obtain sensitive information that
  may lead to further attacks." );
	script_tag( name: "vuldetect", value: "Send a local.startup_log query and check the response." );
	script_tag( name: "solution", value: "Enable authentication or restrict access to the MongoDB service." );
	script_tag( name: "summary", value: "The remote MongoDB service is unprotected." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "remote_active" );
	exit( 0 );
}
require("byte_func.inc.sc");
require("dump.inc.sc");
require("misc_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "mongodb" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
req = raw_string( 0x33, 0x00, 0x00, 0x00, 0x6f, 0x76, 0x61, 0x73, 0x00, 0x00, 0x00, 0x00, 0xd4, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x2e, 0x73, 0x74, 0x61, 0x72, 0x74, 0x75, 0x70, 0x5f, 0x6c, 0x6f, 0x67, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x05, 0x00, 0x00, 0x00, 0x00 );
send( socket: soc, data: req );
buf = recv( socket: soc, length: 4 );
if(!buf || strlen( buf ) != 4){
	close( soc );
	exit( 0 );
}
set_byte_order( BYTE_ORDER_LITTLE_ENDIAN );
size = getdword( blob: buf, pos: 0 );
if(size <= 4 || size > 10485760){
	close( soc );
	exit( 0 );
}
buf = recv( socket: soc, length: ( size - 4 ) );
close( soc );
buf = bin2string( ddata: buf, noprint_replacement: " " );
if(buf){
	buf = ereg_replace( pattern: " {2,}", replace: "\n", string: buf );
}
if(ContainsString( buf, "ovas" ) && ( ContainsString( buf, "mongodb.conf" ) || ContainsString( buf, "hostname" ) || ContainsString( buf, "gitVersion" ) || ContainsString( buf, "buildEnvironment" ) || ContainsString( buf, "sysInfo" ) ) && !ContainsString( buf, "not authorized for query on local.startup_log" ) && !ContainsString( buf, "$err" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

