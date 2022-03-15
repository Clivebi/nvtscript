if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800966" );
	script_version( "$Revision: 11279 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2009-11-05 12:25:48 +0100 (Thu, 05 Nov 2009)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Perl Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of Active or Strawberry Perl.

The script logs in via smb, searches for Active or Strawberry Perl in the
registry and gets the version from registry" );
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
	key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
			 "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
	}
}
if(isnull( key_list )){
	exit( 0 );
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		perlName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( perlName, "Strawberry Perl" )){
			perlLoc = registry_get_sz( key: key + item, item: "InstallLocation" );
			if(!perlLoc){
				perlLoc = "Location not found";
			}
			perlVer = registry_get_sz( key: key + item, item: "Comments" );
			perlVer = eregmatch( pattern: "Strawberry Perl .* ([0-9.]+)", string: perlVer );
			if(!isnull( perlVer[1] )){
				set_kb_item( name: "Strawberry/Perl/Loc", value: perlLoc );
				set_kb_item( name: "Perl/Strawberry_or_Active/Installed", value: TRUE );
				if( ContainsString( os_arch, "x64" ) && !ContainsString( key, "Wow6432Node" ) ){
					set_kb_item( name: "Strawberry64/Perl/Ver", value: perlVer[1] );
					register_and_report_cpe( app: "Strawberry Perl", ver: perlVer[1], base: "cpe:/a:vanilla_perl_project:strawberry_perl:x64:", expr: "^([0-9.]+)", insloc: perlLoc );
				}
				else {
					set_kb_item( name: "Strawberry/Perl/Ver", value: perlVer[1] );
					register_and_report_cpe( app: "Strawberry Perl", ver: perlVer[1], base: "cpe:/a:vanilla_perl_project:strawberry_perl:", expr: "^([0-9.]+)", insloc: perlLoc );
				}
			}
		}
		if(ContainsString( perlName, "ActivePerl" )){
			perlLoc = registry_get_sz( key: key + item, item: "InstallLocation" );
			if(!perlLoc){
				perlLoc = "Location not found";
			}
			perlVer = eregmatch( pattern: "ActivePerl ([0-9.]+)", string: perlName );
			if(!isnull( perlVer[1] )){
				set_kb_item( name: "ActivePerl/Loc", value: perlLoc );
				set_kb_item( name: "Perl/Strawberry_or_Active/Installed", value: TRUE );
				if( ContainsString( os_arch, "x64" ) && !ContainsString( key, "Wow6432Node" ) ){
					set_kb_item( name: "ActivePerl64/Ver", value: perlVer[1] );
					register_and_report_cpe( app: "Active Perl", ver: perlVer[1], base: "cpe:/a:perl:perl:x64:", expr: "^([0-9.]+)", insloc: perlLoc );
				}
				else {
					set_kb_item( name: "ActivePerl/Ver", value: perlVer[1] );
					register_and_report_cpe( app: "Active Perl", ver: perlVer[1], base: "cpe:/a:perl:perl:", expr: "^([0-9.]+)", insloc: perlLoc );
				}
			}
		}
	}
}

