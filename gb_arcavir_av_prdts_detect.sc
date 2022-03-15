if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800719" );
	script_version( "2019-07-31T09:47:07+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-31 09:47:07 +0000 (Wed, 31 Jul 2019)" );
	script_tag( name: "creation_date", value: "2009-06-04 07:18:37 +0200 (Thu, 04 Jun 2009)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "ArcaVir AntiVirus Products Version Detection" );
	script_tag( name: "summary", value: "Detects the installed version of ArcaVir AntiVirus Products on Windows.

The script logs in via smb, searches for ArcaVir in the registry
and gets the install version from the registry." );
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
key = "SOFTWARE\\ArcaBit";
if(!registry_key_exists( key: key )){
	key = "SOFTWARE\\Wow6432Node\\ArcaBit";
	if(!registry_key_exists( key: key )){
		exit( 0 );
	}
}
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
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		arcaName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( arcaName, "ArcaVir" ) || ContainsString( arcaName, "Arcabit" )){
			arcaPath = registry_get_sz( key: key + item, item: "DisplayIcon" );
			if(arcaPath && ContainsString( arcaPath, "arcabit.exe" )){
				arcaPath = arcaPath - "arcabit.exe";
			}
			arcaVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			if(!arcaVer && arcaPath){
				arcaVer = fetch_file_version( sysPath: arcaPath, file_name: "arcabit.exe" );
			}
			if(arcaVer != NULL){
				if(!arcaPath){
					arcaPath = "Could not find the install Location from registry";
				}
				set_kb_item( name: "ArcaVir/AntiVirus/Ver", value: arcaVer );
				cpe = build_cpe( value: arcaVer, exp: "^(9\\..*)", base: "cpe:/a:arcabit:arcavir_2009_antivirus_protection:" );
				if(isnull( cpe )){
					cpe = "cpe:/a:arcabit:arcavir_2009_antivirus_protection";
				}
				if(ContainsString( os_arch, "64" ) && !ContainsString( key, "Wow6432Node" )){
					set_kb_item( name: "ArcaVir64/AntiVirus/Ver", value: arcaVer );
					cpe = build_cpe( value: arcaVer, exp: "^(9\\..*)", base: "cpe:/a:arcabit:arcavir_2009_antivirus_protection:x64:" );
					if(isnull( cpe )){
						cpe = "cpe:/a:arcabit:arcavir_2009_antivirus_protection:x64";
					}
				}
				register_product( cpe: cpe, location: arcaPath );
				log_message( data: build_detection_report( app: arcaName, version: arcaVer, install: arcaPath, cpe: cpe, concluded: arcaVer ) );
			}
		}
	}
}

