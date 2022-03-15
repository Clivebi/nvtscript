if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800015" );
	script_version( "2019-08-19T13:19:17+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-08-19 13:19:17 +0000 (Mon, 19 Aug 2019)" );
	script_tag( name: "creation_date", value: "2008-10-06 13:07:14 +0200 (Mon, 06 Oct 2008)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Mozilla Thunderbird Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of Mozilla Thunderbird on Windows.

  The script logs in via smb, searches for Mozilla Thunderbird in the registry and gets the version from registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("host_details.inc.sc");
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ) {
	key_list = make_list( "SOFTWARE" );
}
else {
	if( ContainsString( os_arch, "x64" ) ) {
		key_list = make_list( "SOFTWARE",
			 "SOFTWARE\\Wow6432Node" );
	}
	else {
		exit( 0 );
	}
}
for key in key_list {
	for regKey in make_list( key + "\\Mozilla",
		 key + "\\mozilla.org" ) {
		if(registry_key_exists( key: regKey )){
			birdVer = registry_get_sz( item: "CurrentVersion", key: regKey + "\\Mozilla Thunderbird" );
			if(birdVer){
				if( IsMatchRegexp( birdVer, "^1\\.5" ) ){
					filePath = registry_get_sz( item: "PathToExe", key: regKey + "\\Mozilla Thunderbird 1.5\\bin" );
					if(!filePath){
						continue;
					}
					tbirdVer = GetVersionFromFile( file: filePath, verstr: "prod" );
					if(!tbirdVer){
						continue;
					}
				}
				else {
					birdVer = eregmatch( pattern: "([0-9]+\\.[0-9.]+(\\s?[a-zA-Z]+[0-9]*)?)", string: birdVer );
					if(birdVer[1]){
						tbirdVer = tolower( birdVer[1] );
					}
				}
				path = registry_get_sz( key: key + "\\Microsoft\\Windows\\CurrentVersion\\", item: "ProgramFilesDir" );
				if(!path){
					continue;
				}
				appPath = path + "\\Mozilla Thunderbird";
				exePath = appPath + "\\update-settings.ini";
				readmeText = smb_read_file( fullpath: exePath, offset: 0, count: 3000 );
				if( readmeText && IsMatchRegexp( readmeText, "comm-esr" ) ){
					set_kb_item( name: "Thunderbird-ESR/Win/Ver", value: tbirdVer );
					set_kb_item( name: "Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed", value: TRUE );
					baseCPE = "cpe:/a:mozilla:thunderbird_esr:";
					appName = "Mozilla Thunderbird ESR";
				}
				else {
					set_kb_item( name: "Thunderbird/Win/Ver", value: tbirdVer );
					set_kb_item( name: "Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed", value: TRUE );
					if( ContainsString( os_arch, "64" ) && !ContainsString( key, "Wow6432Node" ) ){
						set_kb_item( name: "Thunderbird64/Win/Ver", value: tbirdVer );
						baseCPE = "cpe:/a:mozilla:thunderbird:x64:";
					}
					else {
						baseCPE = "cpe:/a:mozilla:thunderbird:";
					}
					appName = "Mozilla Thunderbird";
				}
				cpeVer = str_replace( string: tbirdVer, find: " ", replace: "." );
				cpe = baseCPE + cpeVer;
				tmp_location = tolower( appPath );
				tmp_location = ereg_replace( pattern: "\\\\$", string: tmp_location, replace: "" );
				set_kb_item( name: "Thunderbird/Win/InstallLocations", value: tmp_location );
				register_product( cpe: cpe, location: appPath, service: "smb-login", port: 0 );
				log_message( port: 0, data: build_detection_report( app: appName, version: tbirdVer, install: appPath, cpe: cpe, concluded: tbirdVer ) );
			}
		}
	}
}
exit( 0 );

