if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96076" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-04-09 13:42:26 +0200 (Fri, 09 Apr 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Read /etc/nsswitch.conf and /etc/hosts" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB" );
	script_dependencies( "compliance_tests.sc", "find_service.sc", "gather-package-list.sc" );
	script_tag( name: "summary", value: "This plugin uses ssh to Read /etc/nsswitch.conf and /etc/hosts." );
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
	set_kb_item( name: "GSHB/nsswitch/passwd", value: "error" );
	set_kb_item( name: "GSHB/nsswitch/group", value: "error" );
	set_kb_item( name: "GSHB/nsswitch/hosts", value: "error" );
	set_kb_item( name: "GSHB/dns/hosts", value: "error" );
	set_kb_item( name: "GSHB/dns/log", value: error );
	exit( 0 );
}
windowstest = ssh_cmd( socket: sock, cmd: "cmd /?" );
if(( ContainsString( windowstest, "windows" ) && ContainsString( windowstest, "interpreter" ) ) || ( ContainsString( windowstest, "Windows" ) && ContainsString( windowstest, "interpreter" ) )){
	set_kb_item( name: "GSHB/nsswitch/passwd", value: "windows" );
	set_kb_item( name: "GSHB/nsswitch/group", value: "windows" );
	set_kb_item( name: "GSHB/nsswitch/hosts", value: "windows" );
	set_kb_item( name: "GSHB/dns/hosts", value: "windows" );
	exit( 0 );
}
nsswitch = ssh_cmd( socket: sock, cmd: "grep -v '^ *#' /etc/nsswitch.conf" );
hosts = ssh_cmd( socket: sock, cmd: "grep -v '^ *#' /etc/hosts" );
if(ContainsString( nsswitch, "grep: command not found" )){
	nsswitch = "nogrep";
}
if(ContainsString( hosts, "grep: command not found" )){
	hosts = "nogrep";
}
if(ContainsString( nsswitch, "grep: /etc/nsswitch:" )){
	nsswitch = "none";
}
if(ContainsString( hosts, "grep: /etc/hosts:" )){
	hosts = "none";
}
if(nsswitch != "nogrep" && nsswitch != "none"){
	passwd = egrep( string: nsswitch, pattern: "passwd:", icase: 0 );
	group = egrep( string: nsswitch, pattern: "group:", icase: 0 );
	nshosts = egrep( string: nsswitch, pattern: "hosts:", icase: 0 );
}
if(hosts != "nogrep" && hosts != "none"){
	Lst = split( buffer: hosts, keep: 0 );
	for(i = 0;i < max_index( Lst );i++){
		if(Lst[i] == ""){
			continue;
		}
		hostsLst += Lst[i] + "\n";
	}
}
if(!nsswitch || nsswitch == " "){
	nsswitch = "none";
}
if(!hostsLst){
	hostsLst = "none";
}
set_kb_item( name: "GSHB/nsswitch/passwd", value: passwd );
set_kb_item( name: "GSHB/nsswitch/group", value: group );
set_kb_item( name: "GSHB/nsswitch/hosts", value: nshosts );
set_kb_item( name: "GSHB/dns/hosts", value: hostsLst );
exit( 0 );

