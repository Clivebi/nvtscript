if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96025" );
	script_version( "2019-07-26T13:41:14+0000" );
	script_tag( name: "last_modification", value: "2019-07-26 13:41:14 +0000 (Fri, 26 Jul 2019)" );
	script_tag( name: "creation_date", value: "2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Test if Microsoft Url scan filter is installed(win)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2010 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB", "Tools/Present/wmi" );
	script_dependencies( "smb_reg_service_pack.sc", "GSHB/GSHB_WMI_OSInfo.sc" );
	script_tag( name: "summary", value: "If IIS installed,
  test over WMI if Microsoft Url scan filter is installed:" );
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
	set_kb_item( name: "WMI/IIS_UrlScanFilter", value: "error" );
	set_kb_item( name: "WMI/IIS_UrlScanFilter/log", value: "No access to SMB host.\\nFirewall is activated or there is not a Windows system." );
	exit( 0 );
}
handle = wmi_connect( host: host, username: usrname, password: passwd );
handlereg = wmi_connect_reg( host: host, username: usrname, password: passwd );
if(!handle){
	set_kb_item( name: "WMI/IIS_UrlscanFilter", value: "error" );
	set_kb_item( name: "WMI/IIS_UrlScanFilter/log", value: "wmi_connect: WMI Connect failed." );
	wmi_close( wmi_handle: handle );
	wmi_close( wmi_handle: handlereg );
	exit( 0 );
}
IISVER = wmi_reg_get_dword_val( wmi_handle: handlereg, key: "SOFTWARE\\Microsoft\\InetStp", val_name: "MajorVersion" );
if(!IISVER){
	set_kb_item( name: "WMI/IIS_UrlScanFilter", value: "None" );
	set_kb_item( name: "WMI/IIS_UrlScanFilter/log", value: "IT-Grundschutz: IIS is not installed" );
	wmi_close( wmi_handle: handle );
	wmi_close( wmi_handle: handlereg );
	exit( 0 );
}
windirpath = wmi_os_windir( handle: handle );
if(OSVER < 6){
	val01 = split( buffer: windirpath, sep: "|", keep: 0 );
	val02 = split( buffer: val01[4], sep: "\\", keep: 0 );
	val03 = eregmatch( pattern: ".*[A-Za-z0-9-_/./(/)!$%&=+#@~^]", string: val02[1] );
	pathini = val02[0] + "\\\\" + val03[0] + "\\\\system32\\\\inetsrv\\\\urlscan\\\\urlscan.ini";
	pathdll = val02[0] + "\\\\" + val03[0] + "\\\\system32\\\\inetsrv\\\\urlscan\\\\urlscan.dll";
}
if(OSVER >= 6){
	val01 = split( buffer: windirpath, sep: "\n", keep: 0 );
	val02 = split( buffer: val01[1], sep: "\\", keep: 0 );
	val03 = eregmatch( pattern: ".*[A-Za-z0-9-_/./(/)!$%&=+#@~^]", string: val02[1] );
	pathini = val02[0] + "\\\\" + val03[0] + "\\\\system32\\\\inetsrv\\\\urlscan\\\\urlscan.ini";
	pathdll = val02[0] + "\\\\" + val03[0] + "\\\\system32\\\\inetsrv\\\\urlscan\\\\urlscan.dll";
}
fileExistini = wmi_file_check_file_exists( handle: handle, filePath: pathini );
fileExistdll = wmi_file_check_file_exists( handle: handle, filePath: pathdll );
if( fileExistini == "1" && fileExistdll == "1" ){
	note = val02[0] + "\\" + val03[0] + "\\system32\\inetsrv\\urlscan\\urlscan.ini" + ";";
	note = note + val02[0] + "\\" + val03[0] + "\\system32\\inetsrv\\urlscan\\urlscan.dll" + ";";
}
else {
	note = "FALSE";
}
if( note ) {
	set_kb_item( name: "WMI/IIS_UrlScanFilter", value: note );
}
else {
	set_kb_item( name: "WMI/IIS_UrlScanFilter", value: "None" );
}
wmi_close( wmi_handle: handle );
wmi_close( wmi_handle: handlereg );
exit( 0 );

