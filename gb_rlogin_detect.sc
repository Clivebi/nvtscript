if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113765" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-09-29 12:55:00 +0200 (Tue, 29 Sep 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_name( "rlogin Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Service detection" );
	script_dependencies( "find_service6.sc" );
	script_require_ports( "Services/rlogin", 513 );
	script_tag( name: "summary", value: "Checks whether the rlogin service is running on the target host." );
	script_xref( name: "URL", value: "https://www.ssh.com/ssh/rlogin" );
	script_xref( name: "URL", value: "http://www.ietf.org/rfc/rfc1282.txt" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
nullStr = raw_string( 0x00 );
req1 = "root" + nullStr + "root" + nullStr + "vt100/9600" + nullStr;
port = service_get_port( proto: "rlogin", default: 513 );
soc = open_priv_sock_tcp( dport: port );
if(!soc){
	exit( 0 );
}
send( socket: soc, data: nullStr );
send( socket: soc, data: req1 );
res1 = recv( socket: soc, length: 1 );
res2 = recv( socket: soc, length: 1024 );
close( soc );
if(isnull( res2 )){
	exit( 0 );
}
if( res1 == nullStr && ContainsString( res2, "Password:" ) ){
	detected = TRUE;
}
else {
	if(res1 == nullStr && ( ( ContainsString( res2, "root@" ) && ContainsString( res2, ":~#" ) ) || ContainsString( res2, "Last login: " ) || ( ContainsString( res2, "Linux" ) && ContainsString( res2, " SMP" ) ) )){
		set_kb_item( name: "rlogin/nopass", value: TRUE );
		detected = TRUE;
	}
}
if(detected){
	set_kb_item( name: "rlogin/detected", value: TRUE );
	set_kb_item( name: "rlogin/port", value: port );
	service_register( port: port, proto: "rlogin", message: "A rlogin service seems to be running on this port." );
}
exit( 0 );

