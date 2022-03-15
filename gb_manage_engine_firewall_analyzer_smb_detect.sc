if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107656" );
	script_version( "2020-02-14T10:29:07+0000" );
	script_tag( name: "last_modification", value: "2020-02-14 10:29:07 +0000 (Fri, 14 Feb 2020)" );
	script_tag( name: "creation_date", value: "2019-05-16 16:55:55 +0200 (Thu, 16 May 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "ManageEngine FireWall Analyzer Version Detection (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "Detects the installed version
  of ManageEngine FireWall Analyzer for Windows." );
	script_xref( name: "URL", value: "https://www.manageengine.com/products/firewall" );
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
		if(!appName || !IsMatchRegexp( appName, "ManageEngine FireWall" )){
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
		infopath = location + "\\logs\\productInfoLog_0.txt";
		file_content = smb_read_file( fullpath: infopath, offset: 0, count: 3000 );
		ver = eregmatch( string: file_content, pattern: "Release Version\\s*:\\s*([0-9.]+)" );
		if(ver[1]){
			version = ver[1];
			concluded += "\nFile checked:   " + infopath;
		}
		buildnumber = eregmatch( string: file_content, pattern: "Build Number\\s*:\\s*([0-9]+)" );
		if(buildnumber[1]){
			build = buildnumber[1];
		}
		concluded += "\nDisplayVersion: " + version;
		concluded += "\nBuild Number:   " + build;
		set_kb_item( name: "manageengine/firewall_analyzer/smb/detected", value: TRUE );
		CPE = "cpe:/a:zohocorp:manageengine_firewall_analyzer";
		if( version && build ) {
			CPE += ":" + version + ":b" + build;
		}
		else {
			if(version){
				CPE += ":" + version;
			}
		}
		register_and_report_cpe( app: appName + " Analyzer", ver: version, concluded: concluded, cpename: CPE, insloc: location, regService: "smb-login", regPort: 0 );
		exit( 0 );
	}
}
exit( 0 );

