if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107654" );
	script_version( "2020-02-14T10:29:07+0000" );
	script_tag( name: "last_modification", value: "2020-02-14 10:29:07 +0000 (Fri, 14 Feb 2020)" );
	script_tag( name: "creation_date", value: "2019-05-11 16:49:24 +0200 (Sat, 11 May 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "GE Grid Solutions MeterManager Version Detection (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "Detects the installed version
  of GE Grid Solutions MeterManager for Windows." );
	script_xref( name: "URL", value: "https://www.gegridsolutions.com" );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
require("secpod_smb_func.inc.sc");
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
		appName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(!appName || !IsMatchRegexp( appName, "MeterManager" )){
			continue;
		}
		concluded = "Registry Key:   " + key + item + "\n";
		concluded += "DisplayName:    " + appName;
		location = "unknown";
		version = "unknown";
		loc = registry_get_sz( key: key + item, item: "InstallLocation" );
		if(loc){
			location = loc;
		}
		if(vers = registry_get_sz( key: key + item, item: "DisplayVersion" )){
			version = vers;
			concluded += "\nDisplayVersion: " + vers;
		}
		set_kb_item( name: "gegridsolutions/metermanager/detected", value: TRUE );
		register_and_report_cpe( app: "GE Grid Solutions " + appName, ver: version, concluded: concluded, base: "cpe:/a:ge:metermanager:", expr: "^([0-9.]+)", insloc: location, regService: "smb-login", regPort: 0 );
		exit( 0 );
	}
}
exit( 0 );

