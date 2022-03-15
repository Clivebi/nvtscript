if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805286" );
	script_version( "2019-07-25T12:21:33+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-25 12:21:33 +0000 (Thu, 25 Jul 2019)" );
	script_tag( name: "creation_date", value: "2015-02-23 13:54:02 +0530 (Mon, 23 Feb 2015)" );
	script_name( "BullGuard Internet Security Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  BullGuard Internet Security.

  The script logs in via smb, searches for 'BullGuard Internet Security' in the
  registry, gets installation path from the registry and then reads version
  information from 'version.txt' text file." );
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
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\BullGuard Ltd." )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\BullGuard";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
bgName = registry_get_sz( key: key, item: "DisplayName" );
if(ContainsString( bgName, "BullGuard Internet Security" )){
	bgPath = registry_get_sz( key: key, item: "InstallLocation" );
	if(bgPath){
		bgfile = bgPath + "\\version.txt";
		txtRead = smb_read_file( fullpath: bgfile, offset: 0, count: 50 );
		bgVer = eregmatch( pattern: "^([0-9.]+)", string: txtRead );
		bgVer = bgVer[1];
		if(bgVer){
			set_kb_item( name: "BullGuard/Internet/Security/Ver", value: bgVer );
			cpe = build_cpe( value: bgVer, exp: "^([0-9.]+)", base: "cpe:/a:bullguard:internet_security:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:bullguard:internet_security";
			}
			if(ContainsString( os_arch, "64" )){
				set_kb_item( name: "BullGuard/Internet/Security64/Ver", value: bgVer );
				cpe = build_cpe( value: bgVer, exp: "^([0-9.]+)", base: "cpe:/a:bullguard:internet_security:x64:" );
				if(isnull( cpe )){
					cpe = "cpe:/a:bullguard:internet_security:x64";
				}
			}
			register_product( cpe: cpe, location: bgPath );
			log_message( data: build_detection_report( app: bgName, version: bgVer, install: bgPath, cpe: cpe, concluded: bgVer ) );
		}
	}
}

