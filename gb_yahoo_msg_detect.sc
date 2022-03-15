if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801149" );
	script_version( "2019-11-05T16:13:01+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-11-05 16:13:01 +0000 (Tue, 05 Nov 2019)" );
	script_tag( name: "creation_date", value: "2009-12-08 05:49:24 +0100 (Tue, 08 Dec 2009)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Yahoo! Messenger Version Detection" );
	script_tag( name: "summary", value: "This script detects the installed version of Yahoo! Messenger.

The script logs in via smb, search for the product name in the registry, gets
application Path from the registry and fetches the version from exe file." );
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
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Yahoo! Messenger" );
	key_list2 = make_list( "SOFTWARE\\Yahoo\\pager" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Yahoo! Messenger" );
		key_list2 = make_list( "SOFTWARE\\Wow6432Node\\Yahoo\\pager" );
	}
}
if(isnull( key_list )){
	exit( 0 );
}
for key in key_list {
	ymsgName = registry_get_sz( key: key, item: "DisplayName" );
	if(ContainsString( ymsgName, "Yahoo! Messenger" )){
		ymsgPath = registry_get_sz( key: key, item: "DisplayIcon" );
		ymsgPath = ymsgPath - "\\YahooMessenger.exe,-0";
		for key1 in key_list2 {
			ymsgVer = registry_get_sz( key: key1, item: "ProductVersion" );
			if(!ymsgVer){
				ymsgVer = fetch_file_version( sysPath: ymsgPath, file_name: "YahooMessenger.exe" );
			}
		}
		if(ymsgVer){
			set_kb_item( name: "YahooMessenger/Ver", value: ymsgVer );
			register_and_report_cpe( app: "Yahoo Messenger", ver: ymsgVer, base: "cpe:/a:yahoo:messenger:", expr: "^([0-9.]+)", insloc: ymsgPath );
		}
	}
}

