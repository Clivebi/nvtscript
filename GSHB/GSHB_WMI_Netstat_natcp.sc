if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94251" );
	script_version( "2021-05-07T12:04:10+0000" );
	script_tag( name: "last_modification", value: "2021-05-07 12:04:10 +0000 (Fri, 07 May 2021)" );
	script_tag( name: "creation_date", value: "2015-09-08 13:12:52 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Get Windows TCP Netstat over win_cmd_exec" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_dependencies( "compliance_tests.sc", "smb_login.sc", "smb_nativelanman.sc", "netbios_name_get.sc", "lsc_options.sc" );
	script_mandatory_keys( "Compliance/Launch/GSHB", "SMB/password", "SMB/login" );
	script_require_ports( 139, 445 );
	script_exclude_keys( "SMB/samba" );
	script_tag( name: "summary", value: "Get Windows TCP Netstat over win_cmd_exec" );
	script_tag( name: "qod_type", value: "remote_active" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
if(kb_smb_is_samba()){
	exit( 0 );
}
if(!defined_func( "win_cmd_exec" )){
	exit( 0 );
}
host = get_host_ip();
usrname = kb_smb_login();
domain = kb_smb_domain();
passwd = kb_smb_password();
if(domain){
	usrname = domain + "/" + usrname;
}
if(!host || !usrname || !passwd){
	set_kb_item( name: "GSHB/WMI/NETSTAT/log", value: "nocred" );
	exit( 0 );
}
if(get_kb_item( "win/lsc/disable_win_cmd_exec" )){
	set_kb_item( name: "GSHB/WMI/NETSTAT/log", value: "win_cmd_exec manually disabled" );
	exit( 0 );
}
a = "netstat.exe -na -p tcp";
b = "netstat.exe -na -p tcpv6";
vala = win_cmd_exec( cmd: a, password: passwd, username: usrname );
valb = win_cmd_exec( cmd: b, password: passwd, username: usrname );
report = vala + "\\n" + valb;
set_kb_item( name: "GSHB/WMI/NETSTAT", value: report );
exit( 0 );

