if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107680" );
	script_version( "2021-09-08T14:24:37+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 14:24:37 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-06-08 20:57:30 +0200 (Sat, 08 Jun 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Docker Desktop Community Edition Detection (Windows SMB Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "SMB login-based detection of Docker Desktop Community Edition for Windows." );
	script_xref( name: "URL", value: "https://hub.docker.com/editions/community/docker-ce-desktop-windows" );
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
		app_name = registry_get_sz( key: key + item, item: "DisplayName" );
		if(!app_name || !IsMatchRegexp( app_name, "Docker Desktop" )){
			continue;
		}
		concluded = "Registry Key:   " + key + item + "\n";
		concluded += "DisplayName:    " + app_name;
		location = "unknown";
		version = "unknown";
		if(loc = registry_get_sz( key: key + item, item: "InstallLocation" )){
			location = loc;
		}
		if(vers = registry_get_sz( key: key + item, item: "DisplayVersion" )){
			version = vers;
			concluded += "\nDisplayVersion: " + vers;
		}
		if(buildVer = registry_get_sz( key: key + item, item: "ChannelName" )){
			build = buildVer;
			concluded += "\nChannelName:    " + build;
		}
		set_kb_item( name: "docker/docker_desktop_ce/detected", value: TRUE );
		register_and_report_cpe( app: app_name, ver: version, concluded: concluded, base: "cpe:/a:docker:desktop:", expr: "^([0-9.]+)", insloc: location, regService: "smb-login", regPort: 0 );
		exit( 0 );
	}
}
exit( 0 );

