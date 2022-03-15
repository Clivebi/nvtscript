if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107596" );
	script_version( "2021-01-15T07:13:31+0000" );
	script_tag( name: "last_modification", value: "2021-01-15 07:13:31 +0000 (Fri, 15 Jan 2021)" );
	script_tag( name: "creation_date", value: "2019-02-18 13:08:27 +0100 (Mon, 18 Feb 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Beckhoff TwinCAT Detection (Windows SMB Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "SMB login-based detection of Beckhoff TwinCAT." );
	script_xref( name: "URL", value: "https://www.beckhoff.com/twincat/" );
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
	key_2 = "SOFTWARE\\Beckhoff\\TwinCAT\\System\\";
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
		if(!appName || ( !IsMatchRegexp( appName, "Beckhoff TwinCAT [0-9.]+" ) && appName != "TwinCAT" ) || IsMatchRegexp( appName, "(Remote Manager|Scope|Type System|BlockDiagram)" )){
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
		set_kb_item( name: "beckhoff/twincat/detected", value: TRUE );
		if(appName == "TwinCAT"){
			build = registry_get_dword( key: key_2, item: "Build" );
			if(build){
				split = split( buffer: vers, sep: "." );
			}
			vers2 = ereg_replace( string: vers, pattern: split[max_index( split ) - 1], replace: "" );
			version = vers2 + build;
			concluded += "\n";
			concluded += "\nRegistry Key:   " + key_2;
			concluded += "\nBuildnumber:    " + build;
		}
		register_and_report_cpe( app: appName, ver: version, concluded: concluded, base: "cpe:/a:beckhoff:twincat:", expr: "^([0-9.]+)", insloc: location, regService: "smb-login", regPort: 0 );
		exit( 0 );
	}
}
exit( 0 );

