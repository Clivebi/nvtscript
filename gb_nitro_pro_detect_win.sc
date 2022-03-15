if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811271" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2017-08-04 14:41:18 +0530 (Fri, 04 Aug 2017)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Nitro Pro Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Nitro Pro.

  The script logs in via smb, searches for 'Nitro Pro' in the registry
  and gets the version from 'DisplayVersion' string from registry." );
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
if(!registry_key_exists( key: "SOFTWARE\\Nitro\\Pro" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
for item in registry_enum_keys( key: key ) {
	nitName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( nitName, "Nitro Pro" )){
		nitVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		nitPath = registry_get_sz( key: key + item, item: "InstallLocation" );
		if(!nitPath){
			nitPath = "Couldn find the install location from registry";
		}
		if(nitVer){
			set_kb_item( name: "Nitro/Pro/Win/Ver", value: nitVer );
			cpe = build_cpe( value: nitVer, exp: "^([0-9.]+)", base: "cpe:/a:nitro_software:nitro_pro:" );
			if(!cpe){
				cpe = "cpe:/a:nitro_software:nitro_pro";
			}
			if(ContainsString( os_arch, "64" )){
				set_kb_item( name: "Nitro/Pro64/Win/Ver", value: nitVer );
				cpe = build_cpe( value: nitVer, exp: "^([0-9.]+)", base: "cpe:/a:nitro_software:nitro_pro:x64:" );
				if(!cpe){
					cpe = "cpe:/a:nitro_software:nitro_pro:x64";
				}
			}
			register_product( cpe: cpe, location: nitPath );
			log_message( data: build_detection_report( app: "Nitro Pro", version: nitVer, install: nitPath, cpe: cpe, concluded: nitVer ) );
			exit( 0 );
		}
	}
}

