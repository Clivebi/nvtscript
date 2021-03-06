if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107272" );
	script_version( "$Revision: 13650 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2019-02-14 07:48:40 +0100 (Thu, 14 Feb 2019) $" );
	script_tag( name: "creation_date", value: "2017-12-11 09:50:38 +0700 (Mon, 11 Dec 2017)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "TeamViewer Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  TeamViewer Detection on Windows.

  The script logs in via smb, searches for Teamviewer in the registry, gets the
  installation path from registry and fetches the version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ){
	key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
}
else {
	if(ContainsString( os_arch, "x64" )){
		key = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
	}
}
if(isnull( key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	prdtName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( prdtName, "TeamViewer" )){
		Ver = registry_get_sz( key: key + item, item: "DisplayVersion" );
		loc = registry_get_sz( key: key + item, item: "InstallLocation" );
		if(!loc){
			loc = "Could not determine install path";
		}
		if(Ver != NULL){
			set_kb_item( name: "teamviewer/Ver", value: Ver );
			register_and_report_cpe( app: "TeamViewer", ver: Ver, base: "cpe:/a:teamviewer:teamviewer:", expr: "^([0-9.]+)", insloc: loc );
			exit( 0 );
		}
	}
}
exit( 0 );

