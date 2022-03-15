if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96051" );
	script_version( "$Revision: 10949 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-08-14 11:36:21 +0200 (Tue, 14 Aug 2018) $" );
	script_tag( name: "creation_date", value: "2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Checks over WMI, if hiberfile.sys exists (win)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2010 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB", "Tools/Present/wmi" );
	script_dependencies( "smb_reg_service_pack.sc", "GSHB/GSHB_WMI_OSInfo.sc" );
	script_tag( name: "summary", value: "Checks over WMI, if hiberfile.sys exists (win)." );
	exit( 0 );
}
require("wmi_file.inc.sc");
require("smb_nt.inc.sc");
host = get_host_ip();
usrname = kb_smb_login();
domain = kb_smb_domain();
if(domain){
	usrname = domain + "\\" + usrname;
}
passwd = kb_smb_password();
OSVER = get_kb_item( "WMI/WMI_OSVER" );
OSTYPE = get_kb_item( "WMI/WMI_OSTYPE" );
OSDRIVE = get_kb_item( "WMI/WMI_OSDRIVE" );
filepath = OSDRIVE + "\\\\hiberfile.sys";
if(!OSVER || ContainsString( "none", OSVER )){
	set_kb_item( name: "WMI/hiberfile", value: "error" );
	set_kb_item( name: "WMI/hiberfile/log", value: "No access to SMB host.\\nFirewall is activated or there is not a Windows system." );
	exit( 0 );
}
handle = wmi_connect( host: host, username: usrname, password: passwd );
if(!handle){
	set_kb_item( name: "WMI/hiberfile", value: "error" );
	set_kb_item( name: "WMI/hiberfile/log", value: "wmi_connect: WMI Connect failed." );
	wmi_close( wmi_handle: handle );
	exit( 0 );
}
hibernatefile = wmi_file_check_file_exists( handle: handle, filePath: filepath );
if(!hibernatefile){
	hibernatefile = "none";
}
set_kb_item( name: "WMI/hiberfile", value: hibernatefile );
wmi_close( wmi_handle: handle );
exit( 0 );

