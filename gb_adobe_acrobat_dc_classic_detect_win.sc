if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812923" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2018-02-15 12:59:46 +0530 (Thu, 15 Feb 2018)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Adobe Acrobat DC (Classic Track) Detect (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Adobe Acrobat DC (Classic Track).

  The script logs in via smb, searches for 'Adobe Acrobat DC' in the registry
  and gets the version from 'DisplayVersion' string from registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	script_xref( name: "URL", value: "https://acrobat.adobe.com/us/en/acrobat.html" );
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
		adobeName = registry_get_sz( key: key + item, item: "DisplayName" );
		adobePath = registry_get_sz( key: key + item, item: "InstallLocation" );
		if(ContainsString( adobeName, "Adobe Acrobat DC" ) && IsMatchRegexp( adobePath, "Acrobat [0-9]+" )){
			adobeVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			if(adobeVer){
				set_kb_item( name: "Adobe/AcrobatDC/Classic/Win/Ver", value: adobeVer );
				cpe = build_cpe( value: adobeVer, exp: "^([0-9.]+)", base: "cpe:/a:adobe:acrobat_dc_classic:" );
				if(!cpe){
					cpe = "cpe:/a:adobe:acrobat_dc_classic";
				}
				if(ContainsString( os_arch, "64" ) && !ContainsString( key, "Wow6432Node" )){
					set_kb_item( name: "Adobe/AcrobatDC/Classic64/Win/Ver", value: adobeVer );
					cpe = build_cpe( value: adobeVer, exp: "^([0-9.]+)", base: "cpe:/a:adobe:acrobat_dc_classic:x64:" );
					if(!cpe){
						cpe = "cpe:/a:adobe:acrobat_dc_classic:x64";
					}
				}
				register_product( cpe: cpe, location: adobePath );
				log_message( data: build_detection_report( app: "Adobe Acrobat DC (Classic Track)", version: adobeVer, install: adobePath, cpe: cpe, concluded: adobeVer ) );
				exit( 0 );
			}
		}
	}
}
exit( 0 );

