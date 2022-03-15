if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96002" );
	script_version( "$Revision: 10949 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-08-14 11:36:21 +0200 (Tue, 14 Aug 2018) $" );
	script_tag( name: "creation_date", value: "2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "CD-ROM and FDDlocal User only access (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2010 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB", "Tools/Present/wmi" );
	script_dependencies( "smb_reg_service_pack.sc", "GSHB/GSHB_WMI_OSInfo.sc" );
	script_tag( name: "summary", value: "The script detects whether only local users on CD-ROM and FDD can access." );
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
	set_kb_item( name: "WMI/CD_Allocated", value: "error" );
	set_kb_item( name: "WMI/FD_Allocated", value: "error" );
	set_kb_item( name: "WMI/CD_Allocated/log", value: "No access to SMB host.\\nFirewall is activated or there is not a Windows system." );
	exit( 0 );
}
handle = wmi_connect_reg( host: host, username: usrname, password: passwd );
if(!handle){
	security_message( "wmi_connect: WMI Connect failed." );
	set_kb_item( name: "WMI/CD_Allocated", value: "error" );
	set_kb_item( name: "WMI/FD_Allocated", value: "error" );
	set_kb_item( name: "WMI/CD_Allocated/log", value: "wmi_connect: WMI Connect failed." );
	wmi_close( wmi_handle: handle );
	exit( 0 );
}
ALLOCDKEY = wmi_reg_enum_value( wmi_handle: handle, key: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" );
if( !ALLOCDKEY ){
	log_message( port: 0, proto: "IT-Grundschutz", data: "Registry Path not found." );
	set_kb_item( name: "WMI/CD_Allocated", value: "error" );
	set_kb_item( name: "WMI/FD_Allocated", value: "error" );
	set_kb_item( name: "WMI/CD_Allocated/log", value: "IT-Grundschutz: Registry Path not found." );
	wmi_close( wmi_handle: handle );
	exit( 0 );
}
else {
	if(!ContainsString( ALLOCDKEY, "allocatecdroms" ) || !ContainsString( ALLOCDKEY, "allocatefloppies" )){
		if(!ContainsString( ALLOCDKEY, "allocatecdroms" )){
			allocd = "false";
		}
		if(!ContainsString( ALLOCDKEY, "allocatefloppies" )){
			allofd = "false";
		}
	}
}
if(!allocd){
	allocd = wmi_reg_get_sz( wmi_handle: handle, key: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", key_name: "allocatecdroms" );
}
if(!allofd){
	allofd = wmi_reg_get_sz( wmi_handle: handle, key: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", key_name: "allocatefloppies" );
}
if( allocd == "false" ){
	set_kb_item( name: "WMI/CD_Allocated", value: "off" );
}
else {
	if( allocd == "0" ){
		set_kb_item( name: "WMI/CD_Allocated", value: "off" );
	}
	else {
		if( allocd == 1 ){
			set_kb_item( name: "WMI/CD_Allocated", value: "on" );
		}
		else {
			if(ContainsString( "error", allocd )){
				set_kb_item( name: "WMI/CD_Allocated", value: "error" );
				set_kb_item( name: "WMI/CD_Allocated/log", value: "IT-Grundschutz: Registry Value 'allocatecdroms' not found." );
			}
		}
	}
}
if( allofd == "false" ){
	set_kb_item( name: "WMI/FD_Allocated", value: "off" );
}
else {
	if( allofd == "0" ){
		set_kb_item( name: "WMI/FD_Allocated", value: "off" );
	}
	else {
		if( allofd == 1 ){
			set_kb_item( name: "WMI/FD_Allocated", value: "on" );
		}
		else {
			if(ContainsString( "error", allofd )){
				set_kb_item( name: "WMI/FD_Allocated", value: "error" );
				set_kb_item( name: "WMI/FD_Allocated/log", value: "IT-Grundschutz: Registry Value 'allocatecdroms' not found." );
			}
		}
	}
}
wmi_close( wmi_handle: handle );
exit( 0 );

