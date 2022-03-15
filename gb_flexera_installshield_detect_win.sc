if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809005" );
	script_version( "2021-01-15T07:13:31+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-01-15 07:13:31 +0000 (Fri, 15 Jan 2021)" );
	script_tag( name: "creation_date", value: "2016-08-19 19:16:31 +0530 (Fri, 19 Aug 2016)" );
	script_name( "Flexera InstallShield Detection (Windows SMB Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "SMB login-based detection of Flexera InstallShield." );
	script_tag( name: "qod_type", value: "registry" );
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
if(!registry_key_exists( key: "SOFTWARE\\InstallShield" ) && !registry_key_exists( key: "SOFTWARE\\Wow6432Node\\InstallShield" )){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ) {
	key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
}
else {
	if(ContainsString( os_arch, "x64" )){
		key = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
	}
}
if(isnull( key )){
	exit( 0 );
}
TOTALSEC_LIST = make_list( "^(22\\..+)",
	 "cpe:/a:flexerasoftware:installshield_2015:",
	 "^(21\\..+)",
	 "cpe:/a:flexerasoftware:installshield_2014:",
	 "^(20\\..+)",
	 "cpe:/a:flexerasoftware:installshield_2013:" );
TOTALSEC_MAX = max_index( TOTALSEC_LIST );
for item in registry_enum_keys( key: key ) {
	inshieldName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(IsMatchRegexp( inshieldName, "InstallShield( 2015| 2014| 2013)?$" )){
		inshieldVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		inshieldPath = registry_get_sz( key: key + item, item: "InstallLocation" );
		if(!inshieldPath){
			inshieldPath = "Unable to find the install location from registry";
		}
		if(inshieldVer){
			set_kb_item( name: "Flexera/InstallShield/Win/Ver", value: inshieldVer );
			for(i = 0;i < TOTALSEC_MAX - 1;i = i + 2){
				register_and_report_cpe( app: "Flexera InstallShield", ver: inshieldVer, base: TOTALSEC_LIST[i + 1], expr: TOTALSEC_LIST[i], insloc: inshieldPath );
			}
		}
	}
}
exit( 0 );

