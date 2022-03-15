if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800014" );
	script_version( "2021-06-23T05:58:47+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-23 05:58:47 +0000 (Wed, 23 Jun 2021)" );
	script_tag( name: "creation_date", value: "2008-10-06 13:07:14 +0200 (Mon, 06 Oct 2008)" );
	script_name( "Mozilla Firefox Detection (Windows SMB Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "summary", value: "SMB login-based detection of Mozilla Firefox." );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
checkduplicate = "";
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\Mozilla",
		 "SOFTWARE\\mozilla.org" );
	key_list2 = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Mozilla",
			 "SOFTWARE\\mozilla.org",
			 "SOFTWARE\\Wow6432Node\\Mozilla",
			 "SOFTWARE\\Wow6432Node\\mozilla.org" );
		key_list2 = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
			 "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion" );
	}
}
if(!key_list){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\Mozilla" )){
	if(!registry_key_exists( key: "SOFTWARE\\mozilla.org" )){
		if(!registry_key_exists( key: "SOFTWARE\\Wow6432Node\\Mozilla" )){
			if(!registry_key_exists( key: "SOFTWARE\\Wow6432Node\\mozilla.org" )){
				exit( 0 );
			}
		}
	}
}
for key in key_list {
	ESR = FALSE;
	foxVer = registry_get_sz( key: key + "\\Mozilla Firefox", item: "CurrentVersion" );
	if(!foxVer){
		foxVer = registry_get_sz( key: key + "\\Mozilla", item: "CurrentVersion" );
	}
	if(IsMatchRegexp( foxVer, "([0-9.]+).*[a-zA-Z]." )){
		foxVerlist = eregmatch( string: foxVer, pattern: "([0-9.]+)" );
		if(foxVerlist){
			foxVer = foxVerlist[1];
		}
	}
	if(ContainsString( checkduplicate, foxVer + ", " )){
		continue;
	}
	if(foxVer){
		if(IsMatchRegexp( foxVer, "^1\\.5" )){
			for key in key_list2 {
				exeFile = registry_get_sz( key: key + "\\Uninstall\\Mozilla Firefox (1.5)", item: "InstallLocation" );
				location = exeFile;
				if( location ){
					foxVer = fetch_file_version( sysPath: location, file_name: "firefox.exe" );
				}
				else {
					foxVer = eregmatch( pattern: "([0-9.]+)([0-9a-zA-Z]*)", string: foxVer );
					if(foxVer[1] && foxVer[2]){
						foxVer[0] = foxVer[1] + "." + foxVer[2];
					}
					foxVer = foxVer[0];
				}
			}
		}
		for key in key_list2 {
			path = registry_get_sz( key: key, item: "ProgramFilesDir" );
			if(!path){
				exit( 0 );
			}
			appPath = path + "\\Mozilla Firefox";
			foxVer_check = fetch_file_version( sysPath: appPath, file_name: "firefox.exe" );
			if( ContainsString( foxVer_check, foxVer ) ){
				location = appPath;
				break;
			}
			else {
				location = NULL;
				continue;
			}
		}
		if(!location){
			continue;
		}
		if(!ESR){
			exePath = appPath + "\\application.ini";
			readmeText = smb_read_file( fullpath: exePath, offset: 0, count: 3000 );
			if(IsMatchRegexp( readmeText, "mozilla-esr" )){
				foxVer_check = eregmatch( pattern: "version=([0-9.]+)", string: readmeText );
				if(foxVer_check[1] == foxVer){
					ESR = TRUE;
				}
			}
		}
		if(!ESR){
			exePath = appPath + "\\platform.ini";
			readmeText = smb_read_file( fullpath: exePath, offset: 0, count: 3000 );
			if(IsMatchRegexp( readmeText, "mozilla-esr" )){
				foxVer_check = eregmatch( pattern: "Milestone=([0-9.]+)", string: readmeText );
				if(foxVer_check[1] == foxVer){
					ESR = TRUE;
				}
			}
		}
		if(!ESR){
			exePath = appPath + "\\update-settings.ini";
			readmeText = smb_read_file( fullpath: exePath, offset: 0, count: 3000 );
			if(IsMatchRegexp( readmeText, "mozilla-esr" )){
				ESR = TRUE;
			}
		}
		if( ESR && location ){
			set_kb_item( name: "Firefox-ESR/Win/Ver", value: foxVer );
			set_kb_item( name: "Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed", value: TRUE );
			cpe = build_cpe( value: foxVer, exp: "^([0-9.]+)([0-9a-zA-Z]*)", base: "cpe:/a:mozilla:firefox_esr:" );
			if(!cpe){
				cpe = "cpe:/a:mozilla:firefox_esr";
			}
			if(ContainsString( os_arch, "64" ) && !ContainsString( key, "Wow6432Node" )){
				set_kb_item( name: "Firefox-ESR64/Win/Ver", value: foxVer );
				cpe = build_cpe( value: foxVer, exp: "^([0-9.]+)([0-9a-zA-Z]*)", base: "cpe:/a:mozilla:firefox_esr:x64:" );
				if(!cpe){
					cpe = "cpe:/a:mozilla:firefox_esr:x64";
				}
			}
			appName = "Mozilla Firefox ESR";
		}
		else {
			if(location){
				set_kb_item( name: "Firefox/Win/Ver", value: foxVer );
				set_kb_item( name: "Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed", value: TRUE );
				set_kb_item( name: "Firefox/Linux_or_Win/installed", value: TRUE );
				cpe = build_cpe( value: foxVer, exp: "^([0-9.]+)([0-9a-zA-Z]*)", base: "cpe:/a:mozilla:firefox:" );
				if(!cpe){
					cpe = "cpe:/a:mozilla:firefox";
				}
				if(ContainsString( os_arch, "64" ) && !ContainsString( key, "Wow6432Node" )){
					set_kb_item( name: "Firefox64/Win/Ver", value: foxVer );
					cpe = build_cpe( value: foxVer, exp: "^([0-9.]+)([0-9a-zA-Z]*)", base: "cpe:/a:mozilla:firefox:x64:" );
					if(!cpe){
						cpe = "cpe:/a:mozilla:firefox:x64";
					}
				}
				appName = "Mozilla Firefox";
			}
		}
		if(location){
			set_kb_item( name: "mozilla/firefox/windows/detected", value: TRUE );
			set_kb_item( name: "mozilla/firefox/linux_windows/detected", value: TRUE );
			set_kb_item( name: "mozilla/firefox/windows_macosx/detected", value: TRUE );
			set_kb_item( name: "mozilla/firefox/windows_linux_macosx/detected", value: TRUE );
			checkduplicate += foxVer + ", ";
			set_kb_item( name: "Firefox/Win/InstallLocations", value: tolower( location ) );
			register_product( cpe: cpe, location: location, port: 0, service: "smb-login" );
			log_message( port: 0, data: build_detection_report( app: appName, version: foxVer, install: location, cpe: cpe, concluded: foxVer ) );
		}
	}
}

