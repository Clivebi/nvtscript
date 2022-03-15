if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901010" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-09-02 09:58:59 +0200 (Wed, 02 Sep 2009)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "KVIrc Version Detection (Windows)" );
	script_tag( name: "summary", value: "This script detects the installed version of KVIrc.

  The script logs in via smb, searches for KVIrc in the registry, and gets the version from registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
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
	key_list2 = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
		key_list2 = make_list( "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\" );
	}
}
if(isnull( key_list && key_list2 )){
	exit( 0 );
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		kvircName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( kvircName, "KVIrc" )){
			kvircVer = eregmatch( pattern: "KVIrc ([0-9.]+)", string: kvircName );
			kvircPath = registry_get_sz( key: key + item, item: "UninstallString" );
			kvircPath = "Unknown";
			if( kvircVer[1] ){
				kvircVer = kvircVer[1];
			}
			else {
				for key1 in key_list2 {
					Path = registry_get_sz( key: key1, item: "ProgramFilesDir" );
					exePath = Path + "\\kvirc";
					kvircVer = fetch_file_version( sysPath: exePath, file_name: "kvirc.exe" );
					kvircPath = exePath;
					if(!kvircVer){
						exePath = kvircPath + "\\README.txt";
						readmeText = smb_read_file( fullpath: exePath, offset: 0, count: 500 );
						if(readmeText){
							kvircVer = eregmatch( pattern: "Release ([0-9.]+)", string: readmeText );
							if( kvircVer ){
								kvircVer = kvircVer[1];
							}
							else {
								continue;
							}
						}
					}
				}
			}
			if(kvircVer != NULL){
				set_kb_item( name: "Kvirc/Win/Ver", value: kvircVer );
				cpe = build_cpe( value: kvircVer, exp: "^([0-9.]+)", base: "cpe:/a:kvirc:kvirc:" );
				if(isnull( cpe )){
					cpe = "cpe:/a:kvirc:kvirc";
				}
				register_product( cpe: cpe, location: kvircPath );
				log_message( data: build_detection_report( app: "KVIrc", version: kvircVer, install: kvircPath, cpe: cpe, concluded: kvircVer ) );
			}
		}
	}
}

