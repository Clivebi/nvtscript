if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105429" );
	script_version( "2021-08-09T11:16:04+0000" );
	script_tag( name: "last_modification", value: "2021-08-09 11:16:04 +0000 (Mon, 09 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-10-30 14:08:04 +0100 (Fri, 30 Oct 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Cisco Wireless LAN Controller (WLC) Detection (SSH Login)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "ssh_detect.sc", "gather-package-list.sc" );
	script_require_ports( "Services/ssh", 22 );
	script_mandatory_keys( "ssh/server_banner/available", "Secret/SSH/login", "Secret/SSH/password" );
	script_tag( name: "summary", value: "SSH login-based detection of Cisco Wireless LAN Controller (WLC)." );
	exit( 0 );
}
require("ssh_func.inc.sc");
if(!defined_func( "ssh_shell_open" )){
	exit( 0 );
}
port = kb_ssh_transport();
if(!get_port_state( port )){
	exit( 0 );
}
user = kb_ssh_login();
pass = kb_ssh_password();
if(!user || !pass){
	exit( 0 );
}
for(i = 0;i < 3;i++){
	if(!soc = open_sock_tcp( port )){
		continue;
	}
	sess = ssh_connect( socket: soc );
	if(!sess){
		close( soc );
		continue;
	}
	auth_successful = ssh_userauth( session: sess, login: NULL, password: NULL, privatekey: NULL, passphrase: NULL );
	if(isnull( auth_successful ) || auth_successful){
		close( soc );
		continue;
	}
	shell = ssh_shell_open( sess );
	if(!shell){
		close( soc );
		continue;
	}
	buf = ssh_read_from_shell( sess: sess, pattern: "User:", timeout: 30, retry: 10 );
	if(!buf || !ContainsString( buf, "User" )){
		close( soc );
		continue;
	}
	ssh_shell_write( session: sess, cmd: user + "\n" + pass + "\n" + "show sysinfo\n\nshow inventory\n" );
	buf = ssh_read_from_shell( sess: sess, pattern: "PID", timeout: 30, retry: 10 );
	close( soc );
	if(!buf || !IsMatchRegexp( buf, "Product Name.*Cisco Controller" )){
		exit( 0 );
	}
	set_kb_item( name: "cisco/wlc/detected", value: TRUE );
	set_kb_item( name: "cisco/wlc/ssh-login/detected", value: TRUE );
	set_kb_item( name: "cisco/wlc/ssh-login/port", value: port );
	set_kb_item( name: "ssh/no_linux_shell", value: TRUE );
	set_kb_item( name: "ssh/force/pty", value: TRUE );
	version = "unknown";
	vers = eregmatch( pattern: "Product Version[.]+ ([0-9][^\r\n ]+)", string: buf );
	if(!isnull( vers[1] )){
		version = vers[1];
	}
	mod = eregmatch( string: buf, pattern: "PID: ([^,]+)," );
	if(!isnull( mod[1] )){
		model = mod[1];
	}
	set_kb_item( name: "cisco/wlc/ssh-login/" + port + "/concluded", value: buf );
	set_kb_item( name: "cisco/wlc/ssh-login/" + port + "/version", value: version );
	set_kb_item( name: "cisco/wlc/ssh-login/" + port + "/model", value: model );
	exit( 0 );
}
exit( 0 );

