if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800260" );
	script_version( "$Revision: 10908 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-08-10 17:00:08 +0200 (Fri, 10 Aug 2018) $" );
	script_tag( name: "creation_date", value: "2009-04-02 08:15:32 +0200 (Thu, 02 Apr 2009)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "7zip Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  7zip on Windows.

  The script logs in via smb, searches for 7zip in the registry
  and gets the version from 'DisplayName' string in registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
appExists = FALSE;
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
appKey_list = make_list( "SOFTWARE\\7-Zip",
	 "SOFTWARE\\Wow6432Node\\7-Zip",
	 "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\7-Zip" );
for appKey in appKey_list {
	if(registry_key_exists( key: appKey )){
		appExists = TRUE;
		break;
	}
}
if(!appExists){
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
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		appName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( appName, "7-Zip" )){
			appVer = eregmatch( pattern: "7-Zip (([0-9.]+)\\ ?(beta)?)", string: appName );
			appVer = ereg_replace( pattern: " ", replace: ":", string: appVer[1] );
			appVer = ereg_replace( pattern: ":$", replace: "", string: appVer );
			if(!isnull( appVer )){
				insloc = registry_get_sz( key: key + item, item: "InstallLocation" );
				if(!insloc){
					insloc = "Unable to find the install location";
				}
				set_kb_item( name: "7zip/Win/Ver", value: appVer );
				cpe = build_cpe( value: appVer, exp: "^([0-9.]+):?([a-z]+)?", base: "cpe:/a:7-zip:7-zip:" );
				if(isnull( cpe )){
					cpe = "cpe:/a:7-zip:7-zip";
				}
				if(ContainsString( os_arch, "64" ) && !ContainsString( key, "Wow6432Node" )){
					set_kb_item( name: "7zip64/Win/Ver", value: appVer );
					cpe = build_cpe( value: appVer, exp: "^([0-9.]+):?([a-z]+)?", base: "cpe:/a:7-zip:7-zip:x64:" );
					if(isnull( cpe )){
						cpe = "cpe:/a:7-zip:7-zip:x64";
					}
				}
				tmp_location = tolower( insloc );
				tmp_location = ereg_replace( pattern: "\\\\$", string: tmp_location, replace: "" );
				set_kb_item( name: "7zip/Win/InstallLocations", value: tmp_location );
				register_product( cpe: cpe, location: insloc );
				log_message( data: build_detection_report( app: appName, version: appVer, install: insloc, cpe: cpe, concluded: appVer ) );
			}
		}
	}
}
exit( 0 );

