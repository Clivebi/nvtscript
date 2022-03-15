if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900799" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-12-23 08:41:41 +0100 (Wed, 23 Dec 2009)" );
	script_name( "Ruby Detection (Windows SMB Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "SMB login-based detection of Ruby." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("host_details.inc.sc");
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ){
	key1_list = make_list( "SOFTWARE\\RubyInstaller\\MRI\\" );
	key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key1_list = make_list( "SOFTWARE\\RubyInstaller\\MRI\\",
			 "SOFTWARE\\Wow6432Node\\RubyInstaller\\MRI\\" );
		key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
			 "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
	}
}
for key1 in key1_list {
	if(registry_key_exists( key: key1 )){
		for item in registry_enum_keys( key: key1 ) {
			rubyLoc = registry_get_sz( key: key1 + item, item: "InstallLocation" );
			if(ContainsString( rubyLoc, "Ruby" )){
				patch = registry_get_sz( key: key1 + item, item: "PatchLevel" );
				build = registry_get_sz( key: key1 + item, item: "BuildPlatform" );
				if(patch){
					rubyVer = item + "." + patch;
					set_kb_item( name: "ruby/detected", value: TRUE );
					set_kb_item( name: "ruby/smb-login/detected", value: TRUE );
					set_kb_item( name: "ruby/smb-login/port", value: "445" );
					set_kb_item( name: "ruby/smb-login/445/install", value: "445#---#" + rubyLoc + "#---#" + rubyVer + "#---#" + rubyVer );
					exit( 0 );
				}
			}
		}
	}
}
for key in key_list {
	if(registry_key_exists( key: key )){
		for item in registry_enum_keys( key: key ) {
			rubyName = registry_get_sz( key: key + item, item: "DisplayName" );
			if(ContainsString( rubyName, "Ruby" )){
				rubyVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
				rubyLoc = registry_get_sz( key: key + item, item: "InstallLocation" );
				if(!isnull( rubyVer )){
					concl = rubyVer;
					rubyVer = ereg_replace( pattern: "-", string: rubyVer, replace: "." );
					rubyVer = ereg_replace( pattern: "p", string: rubyVer, replace: "" );
					set_kb_item( name: "ruby/detected", value: TRUE );
					set_kb_item( name: "ruby/smb-login/detected", value: TRUE );
					set_kb_item( name: "ruby/smb-login/port", value: "445" );
					set_kb_item( name: "ruby/smb-login/445/install", value: "445#---#" + rubyLoc + "#---#" + rubyVer + "#---#" + concl );
					exit( 0 );
				}
			}
		}
	}
}
exit( 0 );

