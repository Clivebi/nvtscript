if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817870" );
	script_version( "2020-12-16T06:26:32+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-12-16 06:26:32 +0000 (Wed, 16 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-12-10 11:06:38 +0530 (Thu, 10 Dec 2020)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Adobe Lightroom Classic Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Adobe Lightroom Classic.

  The script logs in via smb, searches for 'Adobe Lightroom Classic' and
  gets the version from 'DisplayVersion' string from registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
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
if(!registry_key_exists( key: "SOFTWARE\\Adobe\\Lightroom" )){
	if(!registry_key_exists( key: "SOFTWARE\\Wow6432Node\\Adobe\\Lightroom" )){
		exit( 0 );
	}
}
if( ContainsString( os_arch, "x86" ) ){
	key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
}
else {
	if(ContainsString( os_arch, "x64" )){
		key = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
	}
}
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	appName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( appName, "Adobe Lightroom Classic" )){
		appVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(appVer){
			insloc = registry_get_sz( key: key + item, item: "InstallLocation" );
			if(!insloc){
				insloc = "Could not find install location.";
			}
			set_kb_item( name: "Adobe/Lightroom/Win/Ver", value: appVer );
			cpe = build_cpe( value: appVer, exp: "^([0-9.]+)", base: "cpe:/a:adobe:lightroom_classic:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:adobe:lightroom_classic";
			}
			register_product( cpe: cpe, location: insloc );
			log_message( data: build_detection_report( app: "Adobe Lightroom Classic", version: appVer, install: insloc, cpe: cpe, concluded: appVer ) );
			exit( 0 );
		}
	}
}
exit( 0 );

