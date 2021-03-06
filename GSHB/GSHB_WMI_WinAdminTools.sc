if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96016" );
	script_version( "$Revision: 10628 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-25 17:52:40 +0200 (Wed, 25 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2009-10-23 12:32:24 +0200 (Fri, 23 Oct 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Find Windows Admin Tools over WMI if IIS installed (win)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2009 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB", "Tools/Present/wmi" );
	script_dependencies( "smb_reg_service_pack.sc", "GSHB/GSHB_WMI_IIS_OpenPorts.sc", "GSHB/GSHB_WMI_OSInfo.sc" );
	script_tag( name: "summary", value: "If IIS installed, find Windows Admin Tools over WMI:

 arp.exe, at.exe, atsvc.exe, cacls.exe, cmd.exe,
 cscript.exe, debug.exe, edit.com, edlin.exe, ftp.exe, finger.exe,
 ipconfig.exe, net.exe, netsh.exe, netstat.exe, nslookup.exe,
 ping.exe, poledit.exe, posix.exe, qbasic.exe, rcp.exe, rdisk.exe,
 regedit.exe, regedt32.exe, regini.exe, regsrv3.exe, rexec.exe,
 route.exe, rsh.exe, runonce.exe, secfixup.exe, syskey.exe,
 telnet.exe, tftp.exe, tracert.exe, tskill.exe, wscript.exe,
 xcopy.exe" );
	exit( 0 );
}
require("wmi_file.inc.sc");
require("wmi_os.inc.sc");
require("smb_nt.inc.sc");
host = get_host_ip();
usrname = kb_smb_login();
domain = kb_smb_domain();
if(domain){
	usrname = domain + "\\" + usrname;
}
passwd = kb_smb_password();
IISVER = get_kb_item( "WMI/IISandPorts" );
OSVER = get_kb_item( "WMI/WMI_OSVER" );
OSTYPE = get_kb_item( "WMI/WMI_OSTYPE" );
if(!OSVER || ContainsString( "none", OSVER )){
	set_kb_item( name: "WMI/AdminTools", value: "error" );
	set_kb_item( name: "WMI/AdminTools/log", value: "No access to SMB host.\\nFirewall is activated or there is not a Windows system." );
	exit( 0 );
}
handle = wmi_connect( host: host, username: usrname, password: passwd );
if(!handle){
	set_kb_item( name: "WMI/AdminTools", value: "error" );
	set_kb_item( name: "WMI/AdminTools/log", value: "wmi_connect: WMI Connect failed." );
	wmi_close( wmi_handle: handle );
	exit( 0 );
}
windirpath = wmi_os_windir( handle: handle );
sysdirpath = wmi_os_sysdir( handle: handle );
if(ContainsString( "None", IISVER )){
	set_kb_item( name: "WMI/AdminTools", value: "inapplicable" );
	set_kb_item( name: "WMI/AdminTools/log", value: "IT-Grundschutz: No IIS installed, Test not needed!" );
	wmi_close( wmi_handle: handle );
	exit( 0 );
}
program = make_list( "arp.exe",
	 "at.exe",
	 "atsvc.exe",
	 "cacls.exe",
	 "cmd.exe",
	 "cscript.exe",
	 "debug.exe",
	 "edit.com",
	 "edlin.exe",
	 "ftp.exe",
	 "finger.exe",
	 "ipconfig.exe",
	 "net.exe",
	 "netsh.exe",
	 "netstat.exe",
	 "nslookup.exe",
	 "ping.exe",
	 "poledit.exe",
	 "posix.exe",
	 "qbasic.exe",
	 "rcp.exe",
	 "rdisk.exe",
	 "regedit.exe",
	 "regedt32.exe",
	 "regini.exe",
	 "regsrv3.exe",
	 "rexec.exe",
	 "route.exe",
	 "rsh.exe",
	 "runonce.exe",
	 "secfixup.exe",
	 "syskey.exe",
	 "telnet.exe",
	 "tftp.exe",
	 "tracert.exe",
	 "tskill.exe",
	 "wscript.exe",
	 "xcopy.exe" );
if( OSVER < 6 ){
	val01 = split( buffer: windirpath, sep: "|", keep: 0 );
	val02 = split( buffer: val01[4], sep: "\\", keep: 0 );
	val03 = eregmatch( pattern: ".*[A-Za-z0-9-_/./(/)!$%&=+#@~^]", string: val02[1] );
	path = val02[0] + "\\\\" + val03[0] + "\\\\";
}
else {
	val01 = split( buffer: windirpath, sep: ":", keep: 0 );
	val03 = eregmatch( pattern: ".*[A-Za-z0-9-_/./(/)!$%&=+#@~^]", string: val01[1] );
	val04 = eregmatch( pattern: "[A-Z]$", string: val01[0] );
	path = val04[0] + ":\\" + val03[0] + "\\\\";
}
if( OSVER < 6 ){
	val11 = split( buffer: sysdirpath, sep: "|", keep: 0 );
	val12 = split( buffer: val11[4], sep: "\\", keep: 0 );
	val13 = eregmatch( pattern: ".*[A-Za-z0-9-_/./(/)!$%&=+#@~^]", string: val12[2] );
	syspath = val12[0] + "\\\\" + val12[1] + "\\\\" + val13[0] + "\\\\";
}
else {
	val11 = split( buffer: sysdirpath, sep: ":", keep: 0 );
	val13 = eregmatch( pattern: ".*[A-Za-z0-9-_///./(/)!$%&=+#@~^]", string: val11[1] );
	val13 = split( buffer: val13[0], sep: "\\", keep: 0 );
	val15 = eregmatch( pattern: "[A-Z]$", string: val11[0] );
	syspath = val15[0] + ":\\\\" + val13[1] + "\\\\" + val13[2] + "\\\\";
}
for p in program {
	fileExist = wmi_file_check_file_exists( handle: handle, filePath: path + p );
	if(fileExist == "1"){
		if(OSVER < 6){
			note = note + val02[0] + "\\" + val03[0] + "\\" + p + "\n";
		}
		if(OSVER >= 6){
			note = note + val04[0] + ":\\" + val03[0] + "\\" + p + "\n";
		}
	}
	fileExist = wmi_file_check_file_exists( handle: handle, filePath: syspath + p );
	if(fileExist == "1"){
		if(OSVER < 6){
			note = note + val12[0] + "\\" + val13[0] + "\\" + p + "\n";
		}
		if(OSVER >= 6){
			note = note + val15[0] + ":\\" + val13[1] + "\\" + val13[2] + "\\" + p + "\n";
		}
	}
}
if( note ) {
	set_kb_item( name: "WMI/AdminTools", value: note );
}
else {
	set_kb_item( name: "WMI/AdminTools", value: "None" );
}
wmi_close( wmi_handle: handle );
exit( 0 );

