if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801128" );
	script_version( "2019-11-05T16:13:01+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-11-05 16:13:01 +0000 (Tue, 05 Nov 2019)" );
	script_tag( name: "creation_date", value: "2009-11-02 14:39:30 +0100 (Mon, 02 Nov 2009)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Gpg4win And Components Version Detection (Windows)" );
	script_tag( name: "summary", value: "This script detects the installed product version of Gpg4win and its components.

  The script logs in via smb, searches for Gpg4win in the registry
  and gets the version from 'DisplayVersion' string in registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
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
	key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\GPG4Win" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\GPG4Win" );
	}
}
if(isnull( key_list )){
	exit( 0 );
}
for key in key_list {
	gpgName = registry_get_sz( key: key, item: "DisplayName" );
	if(ContainsString( gpgName, "Gpg4win" ) || ( ContainsString( gpgName, "GnuPG" ) )){
		gpgVer = registry_get_sz( key: key, item: "DisplayVersion" );
		gpgVer = ereg_replace( pattern: "-", replace: ".", string: gpgVer );
		gpgPath = registry_get_sz( key: key, item: "InstallLocation" );
		if(gpgVer != NULL){
			set_kb_item( name: "Gpg4win_or_Kleopatra/Win/Installed", value: TRUE );
			set_kb_item( name: "Gpg4win/Win/Ver", value: gpgVer );
			register_and_report_cpe( app: "Gpg4win", ver: gpgVer, base: "cpe:/a:gpg4win:gpg4win:", expr: "^([0-9.]+)", insloc: gpgPath );
			if(gpgPath){
				gpgPathK = gpgPath + "\\share\\gpg4win\\README.en.txt";
				txtRead = smb_read_file( fullpath: gpgPathK, offset: 2000, count: 10000 );
				kleoVer = eregmatch( pattern: "Kleopatra: +([0-9.]+)", string: txtRead );
				if(kleoVer[1]){
					set_kb_item( name: "Gpg4win_or_Kleopatra/Win/Installed", value: TRUE );
					set_kb_item( name: "Kleopatra/Win/Ver", value: kleoVer[1] );
					register_and_report_cpe( app: "Kleopatra", ver: kleoVer[1], base: "cpe:/a:kde-apps:kleopatra:", expr: "^([0-9.]+)", insloc: gpgPath );
				}
				gpaVer = eregmatch( pattern: "GPA: +([0-9.]+)", string: txtRead );
				if(gpaVer[1]){
					set_kb_item( name: "GPA/Win/Ver", value: gpaVer[1] );
					register_and_report_cpe( app: "GNU Privacy Assistant", ver: gpaVer[1], base: "cpe:/a:gnu:privacy_assistant:", expr: "^([0-9.]+)", insloc: gpgPath );
				}
			}
		}
	}
}

