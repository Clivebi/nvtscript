if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902425" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2012-02-29 12:08:36 +0530 (Wed, 29 Feb 2012)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Microsoft Windows SMB Accessible Shares" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "smb_login.sc" );
	script_require_keys( "SMB/transport", "SMB/name", "SMB/login", "SMB/password" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "The script detects the Windows SMB Accessible Shares and sets the
  result into KB." );
	exit( 0 );
}
require("smb_nt.inc.sc");
name = kb_smb_name();
domain = kb_smb_domain();
port = kb_smb_transport();
login = kb_smb_login();
pass = kb_smb_password();
if(!port){
	port = 139;
}
if(!get_port_state( port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
r = smb_session_request( soc: soc, remote: name );
if(!r){
	close( soc );
	exit( 0 );
}
prot = smb_neg_prot( soc: soc );
if(!prot){
	close( soc );
	exit( 0 );
}
r = smb_session_setup( soc: soc, login: login, password: pass, domain: "", prot: prot );
if(!r){
	r = smb_session_setup( soc: soc, login: "anonymous", password: pass, domain: "", prot: prot );
	if(!r){
		close( soc );
		exit( 0 );
	}
}
uid = session_extract_uid( reply: r );
if(!uid){
	close( soc );
	exit( 0 );
}
for s in make_list( "A$",
	 "C$",
	 "D$",
	 "ADMIN$",
	 "WINDOWS$",
	 "ROOT$",
	 "WINNT$",
	 "IPC$",
	 "E$" ) {
	r = smb_tconx( soc: soc, name: name, uid: uid, share: s );
	if(r){
		tid = tconx_extract_tid( reply: r );
		if(tid){
			set_kb_item( name: "SMB/Accessible_Shares", value: s );
			report += s + "\n";
		}
	}
}
if(report){
	report = "The following shares were found\n" + report;
	log_message( port: port, data: report );
}
close( soc );

