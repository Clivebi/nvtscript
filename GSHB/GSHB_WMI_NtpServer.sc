if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96015" );
	script_version( "$Revision: 10949 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-08-14 11:36:21 +0200 (Tue, 14 Aug 2018) $" );
	script_tag( name: "creation_date", value: "2009-10-23 12:32:24 +0200 (Fri, 23 Oct 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "WMI NTP Server (win)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2009 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB", "Tools/Present/wmi" );
	script_dependencies( "smb_reg_service_pack.sc", "GSHB/GSHB_WMI_OSInfo.sc" );
	script_tag( name: "summary", value: "Tests WMI NTP Server." );
	exit( 0 );
}
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
	set_kb_item( name: "WMI/NtpServer", value: "error" );
	set_kb_item( name: "WMI/Service/w32time", value: "error" );
	set_kb_item( name: "WMI/NtpServer/log", value: "No access to SMB host.\\nFirewall is activated or there is not a Windows system." );
	exit( 0 );
}
handlereg = wmi_connect_reg( host: host, username: usrname, password: passwd );
handle = wmi_connect( host: host, username: usrname, password: passwd );
if(!handle || !handlereg){
	set_kb_item( name: "WMI/NtpServer", value: "error" );
	set_kb_item( name: "WMI/NtpServer/log", value: "wmi_connect: WMI Connect failed." );
	wmi_close( wmi_handle: handle );
	wmi_close( wmi_handle: handlereg );
	exit( 0 );
}
NtpServer = wmi_reg_get_sz( wmi_handle: handlereg, key: "SYSTEM\\CurrentControlSet\\Services\\W32Time\\Parameters", key_name: "NtpServer" );
query = "select state  from Win32_Service WHERE NAME = \"w32time\"";
w32timeService = wmi_query( wmi_handle: handle, query: query );
if(!NtpServer){
	NtpServer = "None";
}
set_kb_item( name: "WMI/NtpServer", value: NtpServer );
set_kb_item( name: "WMI/Service/w32time", value: w32timeService );
wmi_close( wmi_handle: handle );
wmi_close( wmi_handle: handlereg );
exit( 0 );

