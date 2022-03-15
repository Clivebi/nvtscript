if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811550" );
	script_version( "2019-07-31T09:47:07+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-31 09:47:07 +0000 (Wed, 31 Jul 2019)" );
	script_tag( name: "creation_date", value: "2017-08-03 15:26:47 +0530 (Thu, 03 Aug 2017)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Quick Heal Internet Security Version Detection" );
	script_tag( name: "summary", value: "Detects the installed version of
  Quick Heal Internet Security.

  The script logs in via smb, searches for Quick Heal Internet Security in the
  registry and gets the version from registry." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
if(!registry_key_exists( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Quick Heal Internet Security" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Quick Heal Internet Security\\";
qhName = registry_get_sz( key: key, item: "DisplayName" );
if(ContainsString( qhName, "Quick Heal Internet Security" )){
	qhPath = registry_get_sz( key: key, item: "InstallLocation" );
	if(qhPath){
		qhVer = fetch_file_version( sysPath: qhPath, file_name: "scanner.exe" );
		if(qhVer){
			set_kb_item( name: "QuickHeal/InternetSecurity/Installed", value: TRUE );
			set_kb_item( name: "QuickHeal/InternetSecurity/Ver", value: qhVer );
			register_and_report_cpe( app: qhName, ver: qhVer, base: "cpe:/a:quick_heal:internet_security:", expr: "^([0-9.]+)", insloc: qhPath );
			if(ContainsString( os_arch, "x64" )){
				set_kb_item( name: "QuickHeal/InternetSecurity64/Ver", value: qhVer );
				register_and_report_cpe( app: qhName, ver: qhVer, base: "cpe:/a:quick_heal:internet_security:x64:", expr: "^([0-9.]+)", insloc: qhPath );
			}
		}
	}
}
exit( 0 );

