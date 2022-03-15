if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105611" );
	script_version( "2021-09-20T08:25:27+0000" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "last_modification", value: "2021-09-20 08:25:27 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-04-19 12:49:32 +0200 (Tue, 19 Apr 2016)" );
	script_name( "Weak Encryption Algorithm(s) Supported (SSH)" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_ssh_algos.sc" );
	script_require_ports( "Services/ssh", 22 );
	script_mandatory_keys( "ssh/algos_available" );
	script_xref( name: "URL", value: "https://tools.ietf.org/html/rfc4253#section-6.3" );
	script_xref( name: "URL", value: "https://www.kb.cert.org/vuls/id/958563" );
	script_tag( name: "summary", value: "The remote SSH server is configured to allow / support weak
  encryption algorithm(s)." );
	script_tag( name: "vuldetect", value: "Checks the supported encryption algorithms (client-to-server
  and server-to-client) of the remote SSH server.

  Currently weak encryption algorithms are defined as the following:

  - Arcfour (RC4) cipher based algorithms

  - none algorithm

  - CBC mode cipher based algorithms" );
	script_tag( name: "insight", value: "- The 'arcfour' cipher is the Arcfour stream cipher with 128-bit
  keys. The Arcfour cipher is believed to be compatible with the RC4 cipher [SCHNEIER]. Arcfour
  (and RC4) has problems with weak keys, and should not be used anymore.

  - The 'none' algorithm specifies that no encryption is to be done. Note that this method provides
  no confidentiality protection, and it is NOT RECOMMENDED to use it.

  - A vulnerability exists in SSH messages that employ CBC mode that may allow an attacker to
  recover plaintext from a block of ciphertext." );
	script_tag( name: "solution", value: "Disable the reported weak encryption algorithm(s)." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_active" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
func check_algo( port, type ){
	var encs, port, type;
	if(!type || !port){
		return;
	}
	algos = get_kb_list( "ssh/" + port + "/encryption_algorithms_" + type );
	if(!algos){
		return;
	}
	encs = "";
	algos = sort( algos );
	for found_algo in algos {
		if(ContainsString( found_algo, "none" ) || ContainsString( found_algo, "arcfour" ) || ContainsString( found_algo, "-cbc" )){
			encs += found_algo + "\n";
		}
	}
	if(strlen( encs ) > 0){
		return encs;
	}
}
port = ssh_get_port( default: 22 );
if(rep = check_algo( port: port, type: "client_to_server" )){
	report = "The remote SSH server supports the following weak client-to-server encryption algorithm(s):\n\n" + rep + "\n\n";
}
if(rep = check_algo( port: port, type: "server_to_client" )){
	report += "The remote SSH server supports the following weak server-to-client encryption algorithm(s):\n\n" + rep;
}
if(report){
	security_message( port: port, data: chomp( report ) );
	exit( 0 );
}
exit( 99 );

