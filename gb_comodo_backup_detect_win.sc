if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805342" );
	script_version( "$Revision: 11279 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-06 11:25:59 +0530 (Fri, 06 Mar 2015)" );
	script_name( "Comodo BackUp Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Comodo BackUp.

  The script logs in via smb, searches for Comodo Backup in the
  registry and gets the version from registry" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
require("secpod_smb_func.inc.sc");
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
		appName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( appName, "COMODO BackUp" )){
			cisVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			cisPath = registry_get_sz( key: key + item, item: "InstallLocation" );
			if(!cisPath){
				cisPath = "Could not find the install Location from registry";
			}
			if(cisVer){
				set_kb_item( name: "Comodo/BackUp/Win/Ver", value: cisVer );
				cpe = build_cpe( value: cisVer, exp: "^([0-9.]+)", base: "cpe:/a:comodo:backup:" );
				if(isnull( cpe )){
					cpe = "cpe:/a:comodo:backup";
				}
				if(ContainsString( os_arch, "x64" )){
					set_kb_item( name: "Comodo/BackUp64/Win/Ver", value: cisVer );
					cpe = build_cpe( value: cisVer, exp: "^([0-9.]+)", base: "cpe:/a:comodo:backup:x64:" );
					if(isnull( cpe )){
						cpe = "cpe:/a:comodo:backup:x64";
					}
				}
				register_product( cpe: cpe, location: cisPath );
				log_message( data: build_detection_report( app: "Comodo BackUp", version: cisVer, install: cisPath, cpe: cpe, concluded: cisVer ) );
			}
		}
	}
}

