if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10401" );
	script_version( "2021-01-18T10:34:23+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-01-18 10:34:23 +0000 (Mon, 18 Jan 2021)" );
	script_tag( name: "creation_date", value: "2008-08-27 12:14:14 +0200 (Wed, 27 Aug 2008)" );
	script_name( "SMB Registry : Windows Build Number and Service Pack Version" );
	script_category( ACT_GATHER_INFO );
	script_family( "Windows" );
	script_copyright( "Copyright (C) 2008 Renaud Deraison" );
	script_dependencies( "smb_registry_access.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_access" );
	script_xref( name: "URL", value: "https://docs.greenbone.net/GSM-Manual/gos-20.08/en/scanning.html#requirements-on-target-systems-with-microsoft-windows" );
	script_tag( name: "summary", value: "Detection of the installed Windows build number and
  Service Pack version.

  The script logs in via SMB, reads various registry keys to retrieve the
  Windows build number and Service Pack version." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("host_details.inc.sc");
SCRIPT_DESC = "SMB Registry : Windows Service Pack version";
access = get_kb_item( "SMB/registry_access" );
if(!access){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
if(!registry_key_exists( key: key, query_cache: FALSE, save_cache: TRUE )){
	sleep( 1 );
	if(!registry_key_exists( key: key, query_cache: FALSE, save_cache: TRUE )){
		exit( 0 );
	}
}
if(!winVal = registry_get_sz( key: key, item: "CurrentVersion", query_cache: FALSE, save_cache: TRUE )){
	sleep( 1 );
	winVal = registry_get_sz( key: key, item: "CurrentVersion", query_cache: FALSE, save_cache: TRUE );
}
if(!winName = registry_get_sz( key: key, item: "ProductName", query_cache: FALSE, save_cache: TRUE )){
	sleep( 1 );
	winName = registry_get_sz( key: key, item: "ProductName", query_cache: FALSE, save_cache: TRUE );
}
if(!winBuild = registry_get_sz( key: key, item: "CurrentBuild", query_cache: FALSE, save_cache: TRUE )){
	sleep( 1 );
	winBuild = registry_get_sz( key: key, item: "CurrentBuild", query_cache: FALSE, save_cache: TRUE );
}
if(!csdVer = registry_get_sz( key: key, item: "CSDVersion", query_cache: FALSE, save_cache: TRUE )){
	sleep( 1 );
	csdVer = registry_get_sz( key: key, item: "CSDVersion", query_cache: FALSE, save_cache: TRUE );
}
if(winVal){
	if(winVal != "4.0" && !winName){
		exit( 0 );
	}
	set_kb_item( name: "SMB/WindowsVersion", value: winVal );
}
if(winBuild){
	set_kb_item( name: "SMB/WindowsBuild", value: winBuild );
}
if(winName){
	set_kb_item( name: "SMB/WindowsName", value: winName );
	os_str = winName;
	if(winVal){
		os_str += " " + winVal;
	}
	replace_kb_item( name: "Host/OS/smb", value: os_str );
	replace_kb_item( name: "SMB/OS", value: os_str );
}
if(!csdVer){
	csdVer = "NO_Service_Pack";
}
key = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment";
if(!registry_key_exists( key: key, query_cache: FALSE, save_cache: TRUE )){
	sleep( 1 );
	if(!registry_key_exists( key: key, query_cache: FALSE, save_cache: TRUE )){
		report = "It was not possible to access the registry key '" + key + "' due to e.g. missing access ";
		report += "permissions of the scanning user. Authenticated scans might be incomplete, please check ";
		report += "the references how to correctly configure the user account for Authenticated scans.";
		set_kb_item( name: "SMB/registry_access_missing_permissions/report", value: report );
		set_kb_item( name: "SMB/registry_access_missing_permissions", value: TRUE );
		log_message( port: 0, data: report );
		exit( 0 );
	}
}
if(!arch = registry_get_sz( key: key, item: "PROCESSOR_ARCHITECTURE", query_cache: FALSE, save_cache: TRUE )){
	sleep( 1 );
	arch = registry_get_sz( key: key, item: "PROCESSOR_ARCHITECTURE", query_cache: FALSE, save_cache: TRUE );
}
if( ContainsString( arch, "64" ) ){
	set_kb_item( name: "SMB/Windows/Arch", value: "x64" );
}
else {
	if( ContainsString( arch, "x86" ) ){
		set_kb_item( name: "SMB/Windows/Arch", value: "x86" );
	}
	else {
		if( !arch ){
			set_kb_item( name: "SMB/Windows/Arch", value: "unknown/failed to read PROCESSOR_ARCHITECTURE from key " + key );
		}
		else {
			set_kb_item( name: "SMB/Windows/Arch", value: arch );
		}
	}
}
if(csdVer && !ContainsString( csdVer, "NO_Service_Pack" )){
	set_kb_item( name: "SMB/CSDVersion", value: csdVer );
	csdVer = eregmatch( pattern: "Service Pack [0-9]+", string: csdVer );
	if(!isnull( csdVer[0] )){
		csdVer = csdVer[0];
	}
	if(winVal == "4.0"){
		set_kb_item( name: "SMB/WinNT4/ServicePack", value: csdVer );
	}
	if(winVal == "5.0" && ContainsString( winName, "Microsoft Windows 2000" )){
		set_kb_item( name: "SMB/Win2K/ServicePack", value: csdVer );
	}
	if(winVal == "5.1" && ContainsString( winName, "Microsoft Windows XP" )){
		set_kb_item( name: "SMB/WinXP/ServicePack", value: csdVer );
	}
	if(winVal == "5.2" && ContainsString( winName, "Microsoft Windows Server 2003" ) && ContainsString( arch, "x86" )){
		set_kb_item( name: "SMB/Win2003/ServicePack", value: csdVer );
	}
	if(winVal == "5.2" && ContainsString( winName, "Microsoft Windows Server 2003" ) && ContainsString( arch, "64" )){
		set_kb_item( name: "SMB/Win2003x64/ServicePack", value: csdVer );
	}
	if(winVal == "5.2" && ContainsString( winName, "Microsoft Windows XP" ) && ContainsString( arch, "64" )){
		set_kb_item( name: "SMB/WinXPx64/ServicePack", value: csdVer );
	}
	if(winVal == "6.0" && ContainsString( winName, "Windows Vista" ) && ContainsString( arch, "x86" )){
		set_kb_item( name: "SMB/WinVista/ServicePack", value: csdVer );
	}
	if(winVal == "6.0" && ContainsString( winName, "Windows Vista" ) && ContainsString( arch, "64" )){
		set_kb_item( name: "SMB/WinVistax64/ServicePack", value: csdVer );
	}
	if(winVal == "6.0" && ContainsString( winName, "Windows Server (R) 2008" ) && ContainsString( arch, "x86" )){
		set_kb_item( name: "SMB/Win2008/ServicePack", value: csdVer );
	}
	if(winVal == "6.0" && ContainsString( winName, "Windows Server (R) 2008" ) && ContainsString( arch, "64" )){
		set_kb_item( name: "SMB/Win2008x64/ServicePack", value: csdVer );
	}
	if(winVal == "6.1" && ContainsString( winName, "Windows 7" ) && ContainsString( arch, "x86" )){
		set_kb_item( name: "SMB/Win7/ServicePack", value: csdVer );
	}
	if(winVal == "6.1" && ContainsString( winName, "Windows 7" ) && ContainsString( arch, "64" )){
		set_kb_item( name: "SMB/Win7x64/ServicePack", value: csdVer );
	}
	if(winVal == "6.1" && ContainsString( winName, "Windows Server 2008 R2" ) && ContainsString( arch, "64" )){
		set_kb_item( name: "SMB/Win2008R2/ServicePack", value: csdVer );
	}
	if(winVal == "6.2" && ContainsString( winName, "Windows Server 2012" ) && ContainsString( arch, "64" )){
		set_kb_item( name: "SMB/Win2012/ServicePack", value: csdVer );
	}
	if(winVal == "6.2" && ContainsString( winName, "Windows 8" ) && ContainsString( arch, "x86" )){
		set_kb_item( name: "SMB/Win8/ServicePack", value: csdVer );
	}
	if(winVal == "6.2" && ContainsString( winName, "Windows 8" ) && ContainsString( arch, "64" )){
		set_kb_item( name: "SMB/Win8x64/ServicePack", value: csdVer );
	}
	if(winVal == "6.3" && ContainsString( winName, "Windows 8.1" ) && ContainsString( arch, "x86" )){
		set_kb_item( name: "SMB/Win8.1/ServicePack", value: csdVer );
	}
	if(winVal == "6.3" && ContainsString( winName, "Windows 8.1" ) && ContainsString( arch, "64" )){
		set_kb_item( name: "SMB/Win8.1x64/ServicePack", value: csdVer );
	}
	if(winVal == "6.3" && ContainsString( winName, "Windows 10" ) && ContainsString( arch, "x86" )){
		set_kb_item( name: "SMB/Win10/ServicePack", value: csdVer );
	}
	if(winVal == "6.3" && ContainsString( winName, "Windows 10" ) && ContainsString( arch, "64" )){
		set_kb_item( name: "SMB/Win10x64/ServicePack", value: csdVer );
	}
	if(winVal == "6.3" && ContainsString( winName, "Windows Server 2012 R2" ) && ContainsString( arch, "64" )){
		set_kb_item( name: "SMB/Win2012R2/ServicePack", value: csdVer );
	}
	if(winVal == "6.3" && ContainsString( winName, "Windows Server 2016" ) && ContainsString( arch, "64" )){
		set_kb_item( name: "SMB/Win2016/ServicePack", value: csdVer );
	}
	if(winVal == "6.3" && ContainsString( winName, "Windows Server 2019" ) && ContainsString( arch, "64" )){
		set_kb_item( name: "SMB/Win2019/ServicePack", value: csdVer );
	}
}
if( !isnull( os_str ) && !isnull( csdVer ) && !ContainsString( csdVer, "NO_Service_Pack" ) ){
	report = os_str + " is installed with " + csdVer;
	log_message( port: 0, data: report );
}
else {
	if( !isnull( os_str ) && ContainsString( winName, "Windows 10" ) && winBuild ){
		set_kb_item( name: "SMB/Windows/ServicePack", value: "0" );
		report = os_str + " is installed with build number " + winBuild;
		log_message( port: 0, data: report );
	}
	else {
		if(!isnull( os_str ) && !isnull( csdVer ) && ContainsString( csdVer, "NO_Service_Pack" )){
			SP = "0";
			set_kb_item( name: "SMB/Windows/ServicePack", value: SP );
			report = os_str + " is installed with Service Pack " + SP;
			log_message( port: 0, data: report );
		}
	}
}
exit( 0 );

