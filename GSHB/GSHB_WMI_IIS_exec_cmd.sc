if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96010" );
	script_version( "$Revision: 11349 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-12 09:56:57 +0200 (Wed, 12 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2009-10-23 12:32:24 +0200 (Fri, 23 Oct 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Check for SSIEnableCmdDirective at IIS (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2009 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB", "Tools/Present/wmi" );
	script_dependencies( "smb_reg_service_pack.sc", "GSHB/GSHB_WMI_OSInfo.sc" );
	script_tag( name: "summary", value: "The script detects if the SSI enable Cmd Directive is activated
  for the IIS." );
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
	set_kb_item( name: "WMI/SSIEnableCmdDirective", value: "error" );
	set_kb_item( name: "WMI/SSIEnableCmdDirective/log", value: "No access to SMB host.\\nFirewall is activated or there is not a Windows system." );
	exit( 0 );
}
handle = wmi_connect_reg( host: host, username: usrname, password: passwd );
if(!handle){
	set_kb_item( name: "WMI/SSIEnableCmdDirective", value: "error" );
	set_kb_item( name: "WMI/SSIEnableCmdDirective/log", value: "wmi_connect: WMI Connect failed." );
	wmi_close( wmi_handle: handle );
	exit( 0 );
}
IISVer = wmi_reg_get_dword_val( wmi_handle: handle, key: "SOFTWARE\\\\Microsoft\\\\InetStp", val_name: "MajorVersion" );
if( !IISVer ){
	set_kb_item( name: "WMI/SSIEnableCmdDirective", value: "off" );
	set_kb_item( name: "WMI/SSIEnableCmdDirective/log", value: "IT-Grundschutz: No IIS installed!" );
	wmi_close( wmi_handle: handle );
	exit( 0 );
}
else {
	SSIENCMDKEY = wmi_reg_enum_value( wmi_handle: handle, key: "SYSTEM\\\\CurrentControlSet\\\\Services\\\\W3SVC\\\\Parameters" );
	if(!SSIENCMDKEY){
		set_kb_item( name: "WMI/SSIEnableCmdDirective", value: "error" );
		set_kb_item( name: "WMI/SSIEnableCmdDirective/log", value: "IT-Grundschutz: Registry Path not found." );
		wmi_close( wmi_handle: handle );
		exit( 0 );
	}
	if( IISVer < 6 ){
		ssiencmd = wmi_reg_get_dword_val( wmi_handle: handle, key: "SYSTEM\\\\CurrentControlSet\\\\Services\\\\W3SVC\\\\Parameters", val_name: "SSIEnableCmdDirective" );
		if( !ssiencmd ){
			set_kb_item( name: "GGSHB/SSIEnableCmdDirective", value: "error" );
			set_kb_item( name: "WMI/SSIEnableCmdDirective/log", value: "IT-Grundschutz: Registry Path not found." );
			wmi_close( wmi_handle: handle );
			exit( 0 );
		}
		else {
			if( ssiencmd == 1 ){
				ssiencmd = "on";
			}
			else {
				ssiencmd = "off";
			}
		}
		set_kb_item( name: "WMI/SSIEnableCmdDirective", value: ssiencmd );
	}
	else {
		ssiencmd = wmi_reg_get_dword_val( wmi_handle: handle, key: "SYSTEM\\CurrentControlSet\\Services\\W3SVC\\Parameters", val_name: "SSIEnableCmdDirective" );
		if( !ssiencmd ){
			ssiencmd = "off";
		}
		else {
			if( ssiencmd == 1 ){
				ssiencmd = "on";
			}
			else {
				ssiencmd = "off";
			}
		}
		set_kb_item( name: "WMI/SSIEnableCmdDirective", value: ssiencmd );
	}
}
wmi_close( wmi_handle: handle );
exit( 0 );

