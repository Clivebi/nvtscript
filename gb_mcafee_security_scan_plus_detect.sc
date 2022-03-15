if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810823" );
	script_version( "2021-02-08T14:14:51+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-02-08 14:14:51 +0000 (Mon, 08 Feb 2021)" );
	script_tag( name: "creation_date", value: "2017-03-22 11:19:49 +0530 (Wed, 22 Mar 2017)" );
	script_name( "Intel Security McAfee Security Scan Plus Detection (Windows SMB Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "SMB login-based detection of Intel Security McAfee Security Scan Plus." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ) {
	key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\McAfee Security Scan\\";
}
else {
	if( ContainsString( os_arch, "x64" ) ) {
		key = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\McAfee Security Scan\\";
	}
	else {
		exit( 0 );
	}
}
app_name = registry_get_sz( key: key, item: "HideDisplayName" );
if(!app_name || !ContainsString( app_name, "McAfee Security Scan Plus" )){
	exit( 0 );
}
version = "unknown";
location = "unknown";
vers = registry_get_sz( key: key, item: "DisplayVersion" );
if(vers){
	version = vers;
}
path = registry_get_sz( key: key, item: "InstallDirectory" );
if(path){
	location = path;
}
set_kb_item( name: "McAfee/SecurityScanPlus/Win/Ver", value: version );
register_and_report_cpe( app: "Intel Security McAfee Security Scan Plus", ver: version, base: "cpe:/a:intel:mcafee_security_scan_plus:", expr: "^([0-9.]+)", insloc: location, regService: "smb-login", regPort: 0 );
exit( 0 );

