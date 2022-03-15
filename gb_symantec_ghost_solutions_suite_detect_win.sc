if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808539" );
	script_version( "2019-07-31T09:47:07+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-31 09:47:07 +0000 (Wed, 31 Jul 2019)" );
	script_tag( name: "creation_date", value: "2016-07-07 18:14:15 +0530 (Thu, 07 Jul 2016)" );
	script_name( "Symantec Ghost Solutions Suite (GSS) Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of Symantec
  Ghost Solutions Suite (GSS).

  The script logs in via smb, searches for 'Symantec Ghost Console' installation
  path in the registry and reads the version information from 'ngtray.exe' file." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
	symName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( symName, "Symantec Ghost Console and Standard Tools" )){
		symPath = registry_get_sz( key: key + item, item: "InstallLocation" );
		if(symPath){
			symVer = fetch_file_version( sysPath: symPath, file_name: "ngtray.exe" );
			if(symVer != NULL){
				set_kb_item( name: "Symantec/Ghost/Solution/Suite/Installed", value: symVer );
				cpe = build_cpe( value: symVer, exp: "^([0-9.]+)", base: "cpe:/a:symantec:ghost_solutions_suite:" );
				if(isnull( cpe )){
					cpe = "cpe:/a:symantec:ghost_solutions_suite";
				}
				register_product( cpe: cpe, location: symPath );
				log_message( data: build_detection_report( app: "Symantec Ghost Solution Suite", version: symVer, install: symPath, cpe: cpe, concluded: symVer ) );
				exit( 0 );
			}
		}
	}
}
exit( 0 );

