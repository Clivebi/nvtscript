if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107726" );
	script_version( "2020-02-14T10:29:07+0000" );
	script_tag( name: "last_modification", value: "2020-02-14 10:29:07 +0000 (Fri, 14 Feb 2020)" );
	script_tag( name: "creation_date", value: "2019-10-12 18:16:31 +0200 (Sat, 12 Oct 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Foxit Studio Photo Version Detection (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "Detects the installed version
  of Foxit Studio Photo for Windows." );
	script_xref( name: "URL", value: "https://www.foxitsoftware.com/photo-editor/" );
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
		if(!appName || !IsMatchRegexp( appName, "Foxit Studio Photo" )){
			continue;
		}
		concluded = "Registry Key:   " + key + item + "\n";
		concluded += "DisplayName:    " + appName;
		location = "unknown";
		version = "unknown";
		if(regvers = registry_get_sz( key: key + item, item: "DisplayVersion" )){
			concluded += "\nDisplayVersion: " + regvers;
		}
		loc = registry_get_sz( key: key + item, item: "InstallLocation" );
		if(loc){
			location = loc;
			file = "Foxit Studio Photo.exe";
			vers = fetch_file_version( sysPath: location, file_name: file );
			if(vers && IsMatchRegexp( vers, "^[0-9.]{3,}" )){
				version = vers;
				concluded += "\nFileversion:    " + version + " fetched from " + location + file;
			}
		}
		pub = registry_get_sz( key: key + item, item: "Publisher" );
		if(pub){
			app = pub + " " + appName;
		}
		set_kb_item( name: "foxitsoftware/foxit_studio_photo/detected", value: TRUE );
		register_and_report_cpe( app: app, ver: version, concluded: concluded, base: "cpe:/a:foxitsoftware:foxit_studio_photo:", expr: "^([0-9.]+)", insloc: location, regService: "smb-login", regPort: 0 );
		exit( 0 );
	}
}
exit( 0 );

