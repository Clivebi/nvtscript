if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107357" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-03-10T16:10:49+0000" );
	script_tag( name: "last_modification", value: "2020-03-10 16:10:49 +0000 (Tue, 10 Mar 2020)" );
	script_tag( name: "creation_date", value: "2018-10-29 10:21:41 +0100 (Mon, 29 Oct 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "QLogic QConvergeConsole Version Detection (SMB)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script detects the installed version
  of QLogic QConvergeConsole for Windows." );
	script_xref( name: "URL", value: "https://www.marvell.com/content/dam/marvell/en/public-collateral/ethernet-adaptersandcontrollers/marvell-adapters-qlogic-series-qconvergeconsole-gui-installation-guide-2019-10.pdf" );
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
		if(!appName || !IsMatchRegexp( appName, "QConvergeConsole x64$" )){
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
			concluded += "\nDisplayVersion: " + vers;
			ver = eregmatch( string: vers, pattern: "[0-9]+\\.([0-9.]+)" );
			if(ver[1]){
				version = ver[1];
			}
		}
		set_kb_item( name: "qlogic/qconvergeconsole/detected", value: TRUE );
		register_and_report_cpe( app: appName, ver: version, concluded: concluded, base: "cpe:/a:qlogic:qconvergeconsole:", expr: "^([0-9.]+)", insloc: location, regService: "smb-login", regPort: 0 );
		exit( 0 );
	}
}
exit( 0 );
