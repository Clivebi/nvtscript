if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96082" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-06-02 09:25:45 +0200 (Wed, 02 Jun 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_name( "Run Netstat over an SSH Connection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB" );
	script_dependencies( "compliance_tests.sc", "gather-package-list.sc" );
	script_tag( name: "summary", value: "Run Netstat over an SSH Connection." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = get_preference( "auth_port_ssh" );
if(!port){
	port = ssh_get_port( default: 22, ignore_unscanned: TRUE );
}
sock = ssh_login_or_reuse_connection();
if(!sock){
	error = ssh_get_error();
	if(!error){
		error = "No SSH Port or Connection!";
	}
	log_message( port: port, data: error );
	set_kb_item( name: "GSHB/SSH/NETSTAT", value: "nosock" );
	set_kb_item( name: "GSHB/SSH/NETSTAT/log", value: error );
	exit( 0 );
}
uname = get_kb_item( "ssh/login/uname" );
uname = ereg_replace( pattern: "\n", replace: "", string: uname );
if( !IsMatchRegexp( uname, "SunOS .*" ) ){
	netstat = ssh_cmd( socket: sock, cmd: "netstat -atun" );
	if(ContainsString( netstat, "Zeigt Protokollstatistiken" ) || ContainsString( netstat, "Displays protocol statistics" )){
		netstat = ssh_cmd( socket: sock, cmd: "netstat -atn" );
	}
}
else {
	if(IsMatchRegexp( uname, "SunOS .*" )){
		netstat = ssh_cmd( socket: sock, cmd: "netstat -an -P tcp" );
		END = 0;
		netstats = split( buffer: netstat, keep: 0 );
		for(i = 1;i < max_index( netstats );i++){
			if(IsMatchRegexp( netstats[i], ".*ctive ((U|u)(N|n)(I|i)(X|x)) domain socket.*" )){
				END = 1;
			}
			if(!END){
				netstattcp += netstats[i] + "\n";
			}
		}
		netstat = ssh_cmd( socket: sock, cmd: "netstat -an -P udp" );
		netstats = split( buffer: netstat, keep: 0 );
		END = 0;
		for(i = 1;i < max_index( netstats );i++){
			if(IsMatchRegexp( netstats[i], ".*ctive ((U|u)(N|n)(I|i)(X|x)) domain socket.*" )){
				END = 1;
			}
			if(!END){
				netstatudp += netstats[i] + "\n";
			}
		}
		netstat = netstattcp + "\n" + netstatudp;
	}
}
if(!netstat){
	netstat = "none";
}
set_kb_item( name: "GSHB/SSH/NETSTAT", value: netstat );
exit( 0 );

