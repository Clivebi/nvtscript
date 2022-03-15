if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107107" );
	script_version( "$Revision: 10894 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-08-10 15:09:25 +0200 (Fri, 10 Aug 2018) $" );
	script_tag( name: "creation_date", value: "2016-12-19 11:19:11 +0530 (Mon, 19 Dec 2016)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Nidesoft MP3 Converter Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Nidesoft MP3 Converter.

  The script logs in via smb, searches for Nidesoft MP3 Converter in the registry and gets the version from registry." );
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
		cvName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(IsMatchRegexp( cvName, "Nidesoft MP3 Converter" )){
			cvVer = eregmatch( pattern: "Nidesoft MP3 Converter v([0-9.]+)", string: cvName );
			if(!isnull( cvVer[1] )){
				cvVer = cvVer[1];
			}
			cvPath = registry_get_sz( key: key + item, item: "InstallLocation" );
			if(!cvPath){
				cvPath = "Unable to get the install location from the registry";
			}
			if(cvVer){
				set_kb_item( name: "Nidesoft/Mp3converter/Win/Ver", value: cvVer );
				cpe = build_cpe( value: cvVer, exp: "^([0-9.]+)", base: "cpe:/a:nidesoft:mp3_converter:" );
				if(isnull( cpe )){
					cpe = "cpe:/a:nidesoft:mp3_converter";
				}
				if(ContainsString( os_arch, "x64" ) && !ContainsString( cvPath, "x86" )){
					set_kb_item( name: "Nidesoft/Mp3converter64/Win/Ver", value: cvVer );
					cpe = build_cpe( value: cvVer, exp: "^([0-9.]+)", base: "cpe:/a:nidesoft:mp3_converter:x64:" );
					if(isnull( cpe )){
						cpe = "cpe:/a:nidesoft:mp3_converter:x64";
					}
				}
				register_product( cpe: cpe, location: cvPath );
				log_message( data: build_detection_report( app: "Nidesoft MP3 Converter", version: cvVer, install: cvPath, cpe: cpe, concluded: cvVer ) );
			}
		}
	}
}

