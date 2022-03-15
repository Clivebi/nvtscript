CPE = "cpe:/a:quagga:quagga";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105552" );
	script_version( "$Revision: 12431 $" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Quagga Server No Password" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-20 10:21:00 +0100 (Tue, 20 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-02-16 17:31:57 +0100 (Tue, 16 Feb 2016)" );
	script_category( ACT_ATTACK );
	script_family( "General" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_require_ports( "Services/quagga", 2602 );
	script_tag( name: "summary", value: "The remote Quagga server is not protected with a password." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access to sensitive information or modify system configuration." );
	script_tag( name: "vuldetect", value: "Connect to the remote quagga server and check if a password is needed." );
	script_tag( name: "insight", value: "It was possible to login without a password." );
	script_tag( name: "solution", value: "Set a password." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_dependencies( "gb_quagga_remote_detect.sc" );
	script_tag( name: "qod_type", value: "exploit" );
	script_mandatory_keys( "quagga/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!soc = open_sock_tcp( port )){
	exit( 0 );
}
recv = recv( socket: soc, length: 512 );
if(ContainsString( recv, "Password:" )){
	close( soc );
	exit( 99 );
}
send( socket: soc, data: "?\r\n" );
recv = recv( socket: soc, length: 512 );
if(!ContainsString( recv, "echo" ) || !ContainsString( recv, "enable" ) || !ContainsString( recv, "terminal" )){
	close( soc );
	exit( 0 );
}
report = "It was possible to access the remote Quagga without a password.\n\nData received:\n\n" + recv;
security_message( port: port, data: report );
exit( 0 );

