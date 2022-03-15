if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112390" );
	script_version( "2019-07-31T09:47:07+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-31 09:47:07 +0000 (Wed, 31 Jul 2019)" );
	script_tag( name: "creation_date", value: "2018-10-11 21:32:11 +0200 (Thu, 11 Oct 2018)" );
	script_name( "EPS Viewer Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of EPS Viewer.

  The script logs in via smb, searches for EPS Viewer in the registry and gets the version from its executable." );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
	key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
			 "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
	}
}
if(isnull( key_list )){
	exit( 0 );
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		name = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( name, "EPS Viewer" )){
			version = registry_get_sz( key: key + item, item: "Version" );
			path = registry_get_sz( key: key + item, item: "InstallPath" );
			if(!path){
				path = registry_get_sz( key: key + item, item: "InstallLocation" );
				if(!path){
					path = registry_get_sz( key: key + item, item: "Inno Setup: App Path" );
				}
			}
			if(!version){
				if( path ){
					version = fetch_file_version( sysPath: path, file_name: "EPSViewer.exe" );
				}
				else {
					path = registry_get_sz( key: key, item: "UninstallString" );
					if(path){
						path = path - "unins000.exe";
						version = fetch_file_version( sysPath: path, file_name: "EPSViewer.exe" );
					}
				}
			}
			if(version){
				set_kb_item( name: "IdeaMK/EPSViewer/Win/Installed", value: TRUE );
				if(!path){
					path = "Could not find the install path from registry";
				}
				register_and_report_cpe( app: "ideaMK EPS Viewer", ver: version, concluded: version, base: "cpe:/a:ideamk:eps_viewer:", expr: "^([0-9.]+)", insloc: path );
				exit( 0 );
			}
		}
	}
}

