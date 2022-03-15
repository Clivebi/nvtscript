if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105565" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-03-09 08:39:30 +0100 (Wed, 09 Mar 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "SSH Protocol Algorithms Supported" );
	script_category( ACT_GATHER_INFO );
	script_family( "Service detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "ssh_detect.sc" );
	script_require_ports( "Services/ssh", 22 );
	script_mandatory_keys( "ssh/server_banner/available" );
	script_tag( name: "summary", value: "This script detects which algorithms are supported by the remote SSH Service." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("byte_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ssh_get_port( default: 22 );
types = make_list( "kex_algorithms",
	 "server_host_key_algorithms",
	 "encryption_algorithms_client_to_server",
	 "encryption_algorithms_server_to_client",
	 "mac_algorithms_client_to_server",
	 "mac_algorithms_server_to_client",
	 "compression_algorithms_client_to_server",
	 "compression_algorithms_server_to_client" );
sock = open_sock_tcp( port );
if(!sock){
	exit( 0 );
}
server_version = ssh_exchange_identification( socket: sock );
if(!server_version){
	close( sock );
	exit( 0 );
}
buf = ssh_recv( socket: sock, length: 2000 );
close( sock );
if(isnull( buf )){
	exit( 0 );
}
blen = strlen( buf );
if(blen < 40){
	exit( 0 );
}
if(ord( buf[5] ) != 20){
	exit( 0 );
}
pos = 22;
for typ in types {
	if(pos + 4 > blen){
		break;
	}
	len = getdword( blob: buf, pos: pos );
	pos += 4;
	if(pos + len > blen){
		exit( 0 );
	}
	options = substr( buf, pos, pos + len - 1 );
	pos += len;
	if(!options){
		continue;
	}
	str = split( buffer: options, sep: ",", keep: FALSE );
	for algo in str {
		set_kb_item( name: "ssh/" + port + "/" + typ, value: algo );
	}
	report += typ + ":\n" + options + "\n\n";
}
set_kb_item( name: "ssh/" + port + "/algos_available", value: TRUE );
set_kb_item( name: "ssh/algos_available", value: TRUE );
report = "The following options are supported by the remote ssh service:\n\n" + report;
log_message( port: port, data: report );
exit( 0 );

