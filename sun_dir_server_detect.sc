if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100437" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2010-01-12 12:22:08 +0100 (Tue, 12 Jan 2010)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Sun Java System Directory Server Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "ldap_detect.sc" );
	script_require_ports( "Services/ldap", 389, 636 );
	script_mandatory_keys( "ldap/detected" );
	script_tag( name: "summary", value: "This host is running Sun Java System Directory Server." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("port_service_func.inc.sc");
require("dump.inc.sc");
require("host_details.inc.sc");
require("ldap.inc.sc");
SCRIPT_DESC = "Sun Java System Directory Server Detection";
port = ldap_get_port( default: 389 );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
req = raw_string( 0x30, 0x25, 0x02, 0x01, 0x01, 0x63, 0x20, 0x04, 0x00, 0x0a, 0x01, 0x00, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x01, 0x01, 0x00, 0x87, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x30, 0x00 );
send( socket: soc, data: req );
data = recv( socket: soc, length: 5000 );
close( soc );
if(!data){
	exit( 0 );
}
len = strlen( data );
if(len < 32){
	exit( 0 );
}
linenumber = len / 16;
for(i = 0;i <= linenumber;i++){
	for(j = 0;j < 16;j++){
		if(( i * 16 + j ) < len){
			if( ord( data[i * 16 + j] ) == "48" && ord( data[i * 16 + j + 2] ) == "4" ){
				str += "#";
			}
			else {
				c = data[i * 16 + j];
				if(isprint( c: c )){
					str += c;
				}
			}
		}
	}
}
info = "";
if(ContainsString( str, "Sun-Directory-Server" )){
	set_kb_item( name: "SunJavaDirServer/installed", value: TRUE );
	version = eregmatch( string: str, pattern: "Sun-Directory-Server/([0-9.]+([^#]+)?)" );
	if(!isnull( version[1] )){
		set_kb_item( name: "ldap/" + port + "/SunJavaDirServer", value: version[1] );
		register_host_detail( name: "App", value: "cpe:/a:sun:java_system_directory_server:" + version[1], desc: SCRIPT_DESC );
		info = NASLString( "Sun Java System Directory Server Version '" );
		info += NASLString( version[1] );
		info += NASLString( "' was detected on the remote host\\n" );
	}
	log_message( port: port, data: info );
}
exit( 0 );

