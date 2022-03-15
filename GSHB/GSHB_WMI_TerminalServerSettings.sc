if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96213" );
	script_version( "$Revision: 10949 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-08-14 11:36:21 +0200 (Tue, 14 Aug 2018) $" );
	script_tag( name: "creation_date", value: "2011-12-14 11:30:03 +0100 (Wed, 14 Dec 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Get Windows Terminal Server Settings" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB", "Tools/Present/wmi" );
	script_dependencies( "toolcheck.sc", "GSHB/GSHB_WMI_OSInfo.sc" );
	script_tag( name: "summary", value: "The script reads the Windows Terminal Server Settings." );
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
	error = get_kb_item( "WMI/WMI_OS/log" );
	set_kb_item( name: "WMI/TerminalService", value: "error" );
	if( error ) {
		set_kb_item( name: "WMI/TerminalService/log", value: error );
	}
	else {
		set_kb_item( name: "WMI/TerminalService/log", value: "No access to SMB host.\\nFirewall is activated or there is not a Windows system." );
	}
	exit( 0 );
}
handle = wmi_connect( host: host, username: usrname, password: passwd );
if(!handle){
	set_kb_item( name: "WMI/TerminalService", value: "error" );
	set_kb_item( name: "WMI/TerminalService/log", value: "wmi_connect: WMI Connect failed." );
	wmi_close( wmi_handle: handle );
	exit( 0 );
}
query = "select * from Win32_TerminalServiceSetting";
TSS = wmi_query( wmi_handle: handle, query: query );
if(!TSS){
	TSS = "none";
}
set_kb_item( name: "WMI/TerminalService", value: TSS );
wmi_close( wmi_handle: handle );
exit( 0 );

