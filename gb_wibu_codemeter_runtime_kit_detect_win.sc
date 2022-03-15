if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107542" );
	script_version( "2021-01-15T07:13:31+0000" );
	script_tag( name: "last_modification", value: "2021-01-15 07:13:31 +0000 (Fri, 15 Jan 2021)" );
	script_tag( name: "creation_date", value: "2019-02-09 12:42:28 +0100 (Sat, 09 Feb 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "WIBU-SYSTEMS CodeMeter Runtime Detection (Windows SMB Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_tag( name: "summary", value: "SMB login-based detection of WIBU-SYSTEMS CodeMeter Runtime." );
	script_xref( name: "URL", value: "https://www.wibu.com/products/codemeter/runtime.html" );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("smb_nt.inc.sc");
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
		if(!appName || !IsMatchRegexp( appName, "CodeMeter Runtime" )){
			continue;
		}
		concluded = "  Registry Key:   " + key + item + "\n";
		concluded += "  DisplayName:    " + appName;
		location = "unknown";
		version = "unknown";
		set_kb_item( name: "wibu/codemeter_runtime/detected", value: TRUE );
		set_kb_item( name: "wibu/codemeter_runtime/smb/0/detected", value: TRUE );
		if(loc = registry_get_sz( key: key + item, item: "InstallLocation" )){
			location = loc;
		}
		if(vers = registry_get_sz( key: key + item, item: "DisplayVersion" )){
			regvers = vers;
			concluded += "\n  DisplayVersion: " + vers;
			versionmatch = eregmatch( string: appName, pattern: "(([0-9.]+)([a-z]+)?)" );
			version = versionmatch[1];
			concluded += "\n  Version:        " + version + " " + "extracted from registry key value \"DisplayName\"";
		}
		set_kb_item( name: "wibu/codemeter_runtime/smb/0/version", value: version );
		set_kb_item( name: "wibu/codemeter_runtime/smb/0/location", value: location );
		set_kb_item( name: "wibu/codemeter_runtime/smb/0/concluded", value: concluded );
		exit( 0 );
	}
}
exit( 0 );

