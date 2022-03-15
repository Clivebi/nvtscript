if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105610" );
	script_version( "2021-09-20T11:05:40+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 11:05:40 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-04-19 11:49:32 +0200 (Tue, 19 Apr 2016)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:N/A:N" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_name( "Weak MAC Algorithm(s) Supported (SSH)" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_ssh_algos.sc" );
	script_require_ports( "Services/ssh", 22 );
	script_mandatory_keys( "ssh/algos_available" );
	script_tag( name: "summary", value: "The remote SSH server is configured to allow / support weak MAC
  algorithm(s)." );
	script_tag( name: "vuldetect", value: "Checks the supported MAC algorithms (client-to-server and
  server-to-client) of the remote SSH server.

  Currently weak MAC algorithms are defined as the following:

  - MD5 based algorithms

  - 96-bit based algorithms

  - none algorithm" );
	script_tag( name: "solution", value: "Disable the reported weak MAC algorithm(s)." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_active" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
func check_algo( port, type ){
	var macs, port, type;
	if(!type || !port){
		return;
	}
	algos = get_kb_list( "ssh/" + port + "/mac_algorithms_" + type );
	if(!algos){
		return;
	}
	macs = "";
	algos = sort( algos );
	for found_algo in algos {
		if(ContainsString( found_algo, "none" ) || ContainsString( found_algo, "md5" ) || ContainsString( found_algo, "-96" )){
			macs += found_algo + "\n";
		}
	}
	if(strlen( macs ) > 0){
		return macs;
	}
}
port = ssh_get_port( default: 22 );
if(rep = check_algo( port: port, type: "client_to_server" )){
	report = "The remote SSH server supports the following weak client-to-server MAC algorithm(s):\n\n" + rep + "\n\n";
}
if(rep = check_algo( port: port, type: "server_to_client" )){
	report += "The remote SSH server supports the following weak server-to-client MAC algorithm(s):\n\n" + rep;
}
if(report){
	security_message( port: port, data: chomp( report ) );
	exit( 0 );
}
exit( 99 );

