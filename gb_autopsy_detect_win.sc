if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112295" );
	script_version( "2019-07-31T09:47:07+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-31 09:47:07 +0000 (Wed, 31 Jul 2019)" );
	script_tag( name: "creation_date", value: "2018-06-06 12:56:06 +0200 (Wed, 06 Jun 2018)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Autopsy Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detection of the installed version of Autopsy on Windows.

  The script logs in via SMB and searches the registry for Autopsy installations,
  version and location information." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\Wow6432Node\\The Sleuth Kit" ) && !registry_key_exists( key: "SOFTWARE\\The Sleuth Kit" )){
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
		name = registry_get_sz( key: key + item, item: "DisplayName" );
		if(IsMatchRegexp( name, "^Autopsy" )){
			version = registry_get_sz( key: key + item, item: "DisplayVersion" );
			insloc = registry_get_sz( key: key + item, item: "InstallLocation" );
			if(!version){
				if( !insloc ){
					insloc = "Unable to find the install location";
				}
				else {
					version = fetch_file_version( sysPath: insloc + "bin", file_name: "autopsy.exe" );
				}
			}
			if(version){
				set_kb_item( name: "autopsy/win/detected", value: TRUE );
				base = "cpe:/a:sleuthkit:autopsy:";
				if(ContainsString( os_arch, "64" ) && !ContainsString( key, "Wow6432Node" )){
					base += "x64:";
				}
				register_and_report_cpe( app: "Autopsy", ver: version, concluded: version, base: base, expr: "^([0-9.]+)", insloc: insloc );
			}
		}
	}
}
exit( 0 );

