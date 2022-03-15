if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108442" );
	script_version( "2021-07-29T14:32:53+0000" );
	script_tag( name: "last_modification", value: "2021-07-29 14:32:53 +0000 (Thu, 29 Jul 2021)" );
	script_tag( name: "creation_date", value: "2018-05-16 07:49:52 +0200 (Wed, 16 May 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Authenticated Scan / LSC Info Consolidation (Windows SMB Login)" );
	script_category( ACT_END );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "smb_registry_access.sc", "gb_wmi_access.sc", "smb_reg_service_pack.sc", "lsc_options.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/transport", "SMB/name", "SMB/login", "SMB/password" );
	script_exclude_keys( "SMB/samba" );
	script_xref( name: "URL", value: "https://docs.greenbone.net/GSM-Manual/gos-21.04/en/scanning.html#requirements-on-target-systems-with-microsoft-windows" );
	script_tag( name: "summary", value: "Consolidation and reporting of various technical information
  about authenticated scans / local security checks (LSC) via SMB for Windows targets." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("misc_func.inc.sc");
require("list_array_func.inc.sc");
_kb_login = kb_smb_login();
if(!strlen( _kb_login ) > 0){
	exit( 0 );
}
if(kb_smb_is_samba()){
	exit( 0 );
}
empty_text = "Empty/None";
info_array = make_array();
kb_array = make_array( "WMI/access_successful", "Access via WMI possible", "Tools/Present/wmi", "Extended WMI support available via openvas-smb module", "Tools/Present/smb", "Extended SMB support available via openvas-smb module", "win/lsc/search_portable_apps", "Enable Detection of Portable Apps on Windows", "win/lsc/disable_win_cmd_exec", "Disable the usage of win_cmd_exec for remote commands on Windows", "win/lsc/disable_wmi_search", "Disable file search via WMI on Windows", "SMB/registry_access", "Access to the registry possible", "SMB/WindowsVersion", "Version number of the OS", "SMB/WindowsBuild", "Build number of the OS", "SMB/WindowsName", "Product name of the OS", "SMB/Windows/Arch", "Architecture of the OS", "SMB/workgroup", "Workgroup of the SMB server", "SMB/NTLMSSP", "Enable NTLMSSP", "SMB/dont_send_ntlmv1", "Only use NTLMv2", "SMB/dont_send_in_cleartext", "Never send SMB credentials in clear text", "SMB/registry_access_missing_permissions", "Missing access permissions to the registry", "SMB/CSDVersion", "Name of the most recent service pack installed" );
for kb_item in keys( kb_array ) {
	if( kb = get_kb_item( kb_item ) ){
		if(kb == TRUE){
			kb = "TRUE";
		}
		info_array[kb_array[kb_item] + " (" + kb_item + ")"] = kb;
	}
	else {
		if( kb_item == "SMB/CSDVersion" || kb_item == "SMB/workgroup" || kb_item == "SMB/Windows/Arch" || kb_item == "SMB/WindowsBuild" || kb_item == "SMB/WindowsName" || kb_item == "SMB/WindowsVersion" ){
			info_array[kb_array[kb_item] + " (" + kb_item + ")"] = empty_text;
		}
		else {
			info_array[kb_array[kb_item] + " (" + kb_item + ")"] = "FALSE";
		}
	}
}
if(!domain = kb_smb_domain()){
	domain = empty_text;
}
if( !transport = kb_smb_transport() ) {
	transport = empty_text;
}
else {
	transport += "/tcp";
}
if(!name = kb_smb_name()){
	name = empty_text;
}
if(!sysroot = smb_get_systemroot()){
	sysroot = empty_text;
}
if(!sys32root = smb_get_system32root()){
	sys32root = empty_text;
}
info_array["Port configured for authenticated scans (kb_smb_transport())"] = transport;
info_array["User used for authenticated scans (kb_smb_login())"] = _kb_login;
info_array["Domain used for authenticated scans (kb_smb_domain())"] = domain;
info_array["SMB name used for authenticated scans (kb_smb_name())"] = name;
info_array["Path to the OS SystemRoot (smb_get_systemroot())"] = sysroot;
info_array["Path to the OS SystemRoot for 32bit (smb_get_system32root())"] = sys32root;
success = get_kb_item( "login/SMB/success" );
success_port = get_kb_item( "login/SMB/success/port" );
if( success ){
	info_array["Login via SMB successful (login/SMB/success)"] = "TRUE";
	if(success_port){
		info_array["Port used for the successful login via SMB"] = success_port + "/tcp";
	}
}
else {
	info_array["Login via SMB successful (login/SMB/success)"] = "FALSE";
}
failed = get_kb_item( "login/SMB/failed" );
failed_port = get_kb_item( "login/SMB/failed/port" );
if( failed ){
	info_array["Login via SMB failed (login/SMB/failed)"] = "TRUE";
	if(failed_port){
		info_array["Port used for the failed login via SMB"] = failed_port + "/tcp";
	}
}
else {
	info_array["Login via SMB failed (login/SMB/failed)"] = "FALSE";
}
report = text_format_table( array: info_array, columnheader: make_list( "Description (Knowledge base entry)",
	 "Value/Content" ) );
if(!get_kb_item( "SMB/registry_access" )){
	if(error = get_kb_item( "SMB/registry_access/error" )){
		report += "\n\n" + error;
	}
}
miss_perm = get_kb_item( "SMB/registry_access_missing_permissions" );
if(miss_perm){
	miss_report = get_kb_item( "SMB/registry_access_missing_permissions/report" );
	if(!error){
		report += "\n";
	}
	if(miss_report){
		report += "\n" + miss_report;
	}
}
log_message( port: 0, data: report );
exit( 0 );

