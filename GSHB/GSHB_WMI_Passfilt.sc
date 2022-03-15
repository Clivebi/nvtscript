if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96052" );
	script_version( "$Revision: 10949 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-08-14 11:36:21 +0200 (Tue, 14 Aug 2018) $" );
	script_tag( name: "creation_date", value: "2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Test if passfilt.dll is installed (win)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2010 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB", "Tools/Present/wmi" );
	script_dependencies( "smb_reg_service_pack.sc", "GSHB/GSHB_WMI_OSInfo.sc" );
	script_tag( name: "summary", value: "Test over WMI if passfilt.dll is installed and the
  necessary Registry entry set" );
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
OSVER = get_kb_item( "WMI/WMI_OSVER" );
if(!OSVER || ContainsString( "none", OSVER )){
	set_kb_item( name: "WMI/Passfilt.dll", value: "error" );
	set_kb_item( name: "WMI/Passfilt.reg", value: "error" );
	set_kb_item( name: "WMI/Passfilt/log", value: "No access to SMB host.\\nFirewall is activated or there is not a Windows system." );
	exit( 0 );
}
handle = wmi_connect( host: host, username: usrname, password: passwd );
handlereg = wmi_connect_reg( host: host, username: usrname, password: passwd );
if(!handle){
	set_kb_item( name: "WMI/Passfilt.dll", value: "error" );
	set_kb_item( name: "WMI/Passfilt.reg", value: "error" );
	set_kb_item( name: "WMI/Passfilt/log", value: "wmi_connect: WMI Connect failed." );
	wmi_close( wmi_handle: handle );
	wmi_close( wmi_handle: handlereg );
	exit( 0 );
}
PASSFILT = wmi_reg_get_mul_string_val( wmi_handle: handlereg, key: "SYSTEM\\CurrentControlSet\\Control\\Lsa", val_name: "Notification Packages" );
windirpath = wmi_os_windir( handle: handle );
if(OSVER < 6){
	val01 = split( buffer: windirpath, sep: "|", keep: 0 );
	val02 = split( buffer: val01[4], sep: "\\", keep: 0 );
	val03 = eregmatch( pattern: ".*[A-Za-z0-9-_/./(/)!$%&=+#@~^]", string: val02[1] );
	pathdll = val02[0] + "\\\\" + val03[0] + "\\\\system32\\\\passfilt.dll";
}
if(OSVER >= 6){
	val01 = split( buffer: windirpath, sep: "\n", keep: 0 );
	val02 = split( buffer: val01[1], sep: "\\", keep: 0 );
	val03 = eregmatch( pattern: ".*[A-Za-z0-9-_/./(/)!$%&=+#@~^]", string: val02[1] );
	pathdll = val02[0] + "\\\\" + val03[0] + "\\\\system32\\\\passfilt.dll";
}
fileExistdll = wmi_file_check_file_exists( handle: handle, filePath: pathdll );
if( fileExistdll == "1" ){
	note = note + val02[0] + "\\" + val03[0] + "\\system32\\passfilt.dll";
}
else {
	note = "FALSE";
}
if(!note){
	note = "None";
}
if(!PASSFILT){
	PASSFILT = "None";
}
set_kb_item( name: "WMI/Passfilt.dll", value: note );
set_kb_item( name: "WMI/Passfilt.reg", value: PASSFILT );
wmi_close( wmi_handle: handle );
wmi_close( wmi_handle: handlereg );
exit( 0 );

