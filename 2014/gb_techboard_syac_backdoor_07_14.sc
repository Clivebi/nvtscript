if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105059" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "$Revision: 14185 $" );
	script_name( "Backdoor access to Techboard/Syac devices" );
	script_xref( name: "URL", value: "http://blog.emaze.net/2014/07/backdoor-techboardsyac.html" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-14 14:43:25 +0100 (Thu, 14 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-07-08 15:03:46 +0200 (Tue, 08 Jul 2014)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "General" );
	script_copyright( "This script is Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc" );
	script_require_ports( 7339 );
	script_tag( name: "impact", value: "Clients can leverage this service to execute arbitrary commands on the
  underlying Linux system, with root privileges." );
	script_tag( name: "vuldetect", value: "Send a special request to port 7339 and check the response." );
	script_tag( name: "insight", value: "Affected devices include a backdoor service listening on TCP port 7339." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "summary", value: "Backdoor access to Techboard/Syac devices" );
	exit( 0 );
}
port = 7339;
if(!get_port_state( port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
send( socket: soc, data: "KNOCK-KNOCK-ANYONETHERE?\x00" );
buf = recv( socket: soc, length: 12 );
close( soc );
if(!buf || strlen( buf ) != 12){
	exit( 0 );
}
if(hexstr( substr( buf, 8, 12 ) ) == "000aae60"){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

