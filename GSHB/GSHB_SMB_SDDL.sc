if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96041" );
	script_version( "$Revision: 10949 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-08-14 11:36:21 +0200 (Tue, 14 Aug 2018) $" );
	script_tag( name: "creation_date", value: "2009-10-23 12:32:24 +0200 (Fri, 23 Oct 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "File and Folder ACL (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2009 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Tools/Present/wmi", "Compliance/Launch/GSHB" );
	script_dependencies( "smb_reg_service_pack.sc", "GSHB/GSHB_WMI_OSInfo.sc" );
	script_tag( name: "summary", value: "The script List File and Folder ACL (Windows)." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("smb_nt.inc.sc");
host = get_host_ip();
usrname = kb_smb_name();
domain = kb_smb_domain();
if(domain){
	usrname = domain + "\\" + usrname;
}
passwd = kb_smb_password();
OSVER = get_kb_item( "WMI/WMI_OSVER" );
osdrive = get_kb_item( "WMI/WMI_OSDRIVE" );
oswindir = get_kb_item( "WMI/WMI_OSWINDIR" );
pattern = osdrive + "\\\\";
winname = ereg_replace( pattern: pattern, string: oswindir, replace: "" );
rootname = winname + "\\..";
autoexec = "autoexec.bat";
share = ereg_replace( pattern: ":", string: osdrive, replace: "$" );
if(!OSVER || ContainsString( "none", OSVER )){
	set_kb_item( name: "GSHB/WINSDDL", value: "error" );
	set_kb_item( name: "GSHB/ROOTSDDL", value: "error" );
	set_kb_item( name: "GSHB/AUTOEXECSDDL", value: "error" );
	set_kb_item( name: "GSHB/WINSDDL/log", value: "No access to SMB host.\\nFirewall is activated or there is not a Windows system." );
	exit( 0 );
}
smbhandle = smb_connect( host: host, share: share, username: usrname, password: passwd );
if(!smbhandle){
	set_kb_item( name: "GSHB/WINSDDL", value: "error" );
	set_kb_item( name: "GSHB/ROOTSDDL", value: "error" );
	set_kb_item( name: "GSHB/AUTOEXECSDDL", value: "error" );
	set_kb_item( name: "GSHB/WINSDDL/log", value: "smb_connect: SMB Connect failed." );
	smb_close( smb_handle: smbhandle );
	exit( 0 );
}
osdrive = get_kb_item( "WMI/WMI_OSDRIVE" );
oswindir = get_kb_item( "WMI/WMI_OSWINDIR" );
pattern = osdrive + "\\\\";
winname = ereg_replace( pattern: pattern, string: oswindir, replace: "" );
rootname = winname + "\\..";
autoexec = "autoexec.bat";
winsddl = smb_file_SDDL( smb_handle: smbhandle, filename: winname );
rootsddl = smb_file_SDDL( smb_handle: smbhandle, filename: rootname );
autoexecsddl = smb_file_SDDL( smb_handle: smbhandle, filename: autoexec );
if(!winsddl){
	winsddl = "None";
}
if(!rootsddl){
	rootsddl = "None";
}
if(!autoexecsddl){
	autoexecsddl = "None";
}
set_kb_item( name: "GSHB/AUTOEXECSDDL", value: autoexecsddl );
set_kb_item( name: "GSHB/WINSDDL", value: winsddl );
set_kb_item( name: "GSHB/ROOTSDDL", value: rootsddl );
smb_close( smb_handle: smbhandle );
set_kb_item( name: "GSHB/WINSDDL/stat", value: "ok" );
exit( 0 );

