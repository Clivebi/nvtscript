if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804180" );
	script_version( "2019-07-31T09:47:07+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-31 09:47:07 +0000 (Wed, 31 Jul 2019)" );
	script_tag( name: "creation_date", value: "2013-12-30 17:37:18 +0530 (Mon, 30 Dec 2013)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Quick Heal Anti-Virus Version Detection" );
	script_tag( name: "summary", value: "Detects the installed version of Quick Heal Anti-Virus.

The script logs in via smb, searches for Quick Heal in the registry and gets
the version from registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
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
if(!registry_key_exists( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Quick Heal AntiVirus Pro" )){
	exit( 0 );
}
key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Quick Heal AntiVirus Pro\\" );
if(isnull( key_list )){
	exit( 0 );
}
for key in key_list {
	qhName = registry_get_sz( key: key, item: "DisplayName" );
	if(ContainsString( qhName, "Quick Heal AntiVirus Pro" )){
		qhPath = registry_get_sz( key: key, item: "InstallLocation" );
		if(qhPath){
			qhVer = fetch_file_version( sysPath: qhPath, file_name: "scanner.exe" );
			if(qhVer){
				set_kb_item( name: "QuickHeal/Antivirus6432/Pro/Installed", value: TRUE );
				set_kb_item( name: "QuickHeal/Antivirus/Pro", value: qhVer );
				register_and_report_cpe( app: qhName, ver: qhVer, base: "cpe:/a:quickheal:antivirus_pro:", expr: "^([0-9.]+)", insloc: qhPath );
				if(ContainsString( os_arch, "x64" )){
					set_kb_item( name: "QuickHeal/Antivirus64/Pro", value: qhVer );
					register_and_report_cpe( app: qhName, ver: qhVer, base: "cpe:/a:quickheal:antivirus_pro:x64:", expr: "^([0-9.]+)", insloc: qhPath );
				}
			}
		}
	}
}

