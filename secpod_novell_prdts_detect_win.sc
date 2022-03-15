if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900340" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-04-24 16:23:28 +0200 (Fri, 24 Apr 2009)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Novell Multiple Products Version Detection" );
	script_tag( name: "summary", value: "This script detects the installed version of Novell Products." );
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
if(!registry_key_exists( key: "SOFTWARE\\Novell" )){
	if(!registry_key_exists( key: "SOFTWARE\\Novell-iPrint" )){
		if(!registry_key_exists( key: "SOFTWARE\\Wow6432Node\\Novell" )){
			exit( 0 );
		}
	}
}
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ){
	key_novell = make_list( "SOFTWARE\\Novell" );
	key_iprint = "SOFTWARE\\Novell-iPrint";
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_novell = make_list( "SOFTWARE\\Novell",
			 "SOFTWARE\\Wow6432Node\\Novell" );
		key_iprint = "SOFTWARE\\Novell-iPrint";
	}
}
for key in key_novell {
	if(registry_key_exists( key: key + "\\NDS" )){
		eDirName = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" + "\\Uninstall\\NDSonNT", item: "DisplayName" );
		if(ContainsString( eDirName, "eDirectory" )){
			eDirVer = eregmatch( pattern: "([0-9]\\.[0-9.]+).?(SP[0-9])?", string: eDirName );
			eDirPath = "Could not find install location";
			if( eDirVer[1] != NULL && eDirVer[2] != NULL ){
				eDirVer = eDirVer[1] + "." + eDirVer[2];
			}
			else {
				eDirVer = eDirVer[1];
			}
			if(eDirVer){
				set_kb_item( name: "Novell/eDir/Win/Installed", value: TRUE );
				if( ContainsString( os_arch, "x64" ) ){
					set_kb_item( name: "Novell/eDir/Win64/Ver", value: eDirVer );
					register_and_report_cpe( app: "Novell eDirectory", ver: eDirVer, concluded: eDirVer, base: "cpe:/a:novell:edirectory:x64:", expr: "^([0-9.]+([a-z0-9]+)?)", insloc: eDirPath );
				}
				else {
					set_kb_item( name: "Novell/eDir/Win/Ver", value: eDirVer );
					register_and_report_cpe( app: "Novell eDirectory", ver: eDirVer, concluded: eDirVer, base: "cpe:/a:novell:edirectory:", expr: "^([0-9.]+([a-z0-9]+)?)", insloc: eDirPath );
				}
			}
		}
	}
	if(registry_key_exists( key: key )){
		clientVer = registry_get_sz( key: key + "\\NetWareWorkstation\\CurrentVersion", item: "ProductName" );
		clientPath = "Could not find install location";
		if(!clientVer){
			clientVer = registry_get_sz( key: key + "\\Client\\Version", item: "ProductName" );
		}
		if( ContainsString( clientVer, "Novell Client" ) ){
			clientVersion = eregmatch( pattern: "([0-9]\\.[0-9.]+).?(SP[0-9]+)?", string: clientVer );
			if( clientVersion[1] != NULL && clientVersion[2] != NULL ){
				clientVersion = clientVersion[1] + "." + clientVersion[2];
			}
			else {
				if(IsMatchRegexp( clientVersion[1], "[0-9]+" )){
					clientVersion = clientVersion[1];
				}
			}
			if(clientVersion[0] == NULL){
				clientVersion = eregmatch( pattern: "([0-9]+).(SP[0-9]+)?", string: clientVer );
				if(clientVersion[1] != NULL && clientVersion[2] != NULL){
					clientVersion = clientVersion[1] + "." + clientVersion[2];
				}
			}
		}
		else {
			clientVersion = registry_get_sz( key: key, item: "CurrentVersion" );
		}
		if(clientVersion){
			set_kb_item( name: "Novell/Client/Installed", value: TRUE );
			if( ContainsString( os_arch, "x64" ) ){
				set_kb_item( name: "Novell/Client64/Ver", value: clientVer );
				register_and_report_cpe( app: "Novell Client", ver: clientVersion, concluded: clientVer, base: "cpe:/a:novell:client:x64:", expr: "^([0-9.]+([a-z0-9]+)?)", insloc: clientPath );
			}
			else {
				set_kb_item( name: "Novell/Client/Ver", value: clientVer );
				register_and_report_cpe( app: "Novell Client", ver: clientVersion, concluded: clientVer, base: "cpe:/a:novell:client:", expr: "^([0-9.]+([a-z0-9]+)?)", insloc: clientPath );
			}
		}
	}
	if(registry_key_exists( key: key + "\\NetIdentity" )){
		unins_key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
		if(ContainsString( os_arch, "x64" )){
			unins_key = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
		}
		for item in registry_enum_keys( key: unins_key ) {
			netidName = registry_get_sz( key: unins_key + item, item: "DisplayName" );
			if(ContainsString( netidName, "NetIdentity" )){
				netidVer = eregmatch( pattern: "([0-9]\\.[0-9.]+)", string: netidName );
				netidPath = registry_get_sz( key: unins_key + item, item: "InstallLocation" );
				if(!netidPath){
					netidPath = "Could not find install location";
				}
				if(netidVer[1] != NULL){
					set_kb_item( name: "Novell/NetIdentity/Installed", value: TRUE );
					set_kb_item( name: "Novell/NetIdentity/Ver", value: netidVer[1] );
					register_and_report_cpe( app: "Novell NetIdentity", ver: netidVer[1], concluded: netidVer[0], base: "cpe:/a:novell:netidentity_client:", expr: "^([0-9.]+)", insloc: netidPath );
					buildVer = registry_get_sz( key: unins_key + item, item: "DisplayVersion" );
					if(!buildVer){
						buildVer = registry_get_sz( key: key + "NetIdentity", item: "Version" );
					}
					if(buildVer){
						set_kb_item( name: "Novell/NetIdentity/Build/Ver", value: buildVer );
					}
				}
			}
		}
	}
	if(registry_key_exists( key: key + "\\GroupWise" )){
		gcPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" + "\\App Paths\\GrpWise.exe", item: "Path" );
		if(gcPath != NULL){
			gcVer = fetch_file_version( sysPath: gcPath, file_name: "GrpWise.exe" );
			if(gcVer != NULL){
				set_kb_item( name: "Novell/Groupwise/Client/Win/Installed", value: TRUE );
				set_kb_item( name: "Novell/Groupwise/Client/Win/Ver", value: gcVer );
				register_and_report_cpe( app: "Novell Groupwise Client", ver: gcVer, concluded: gcVer, base: "cpe:/a:novell:groupwise:", expr: "^([0-9.]+)", insloc: gcPath );
			}
		}
	}
	if(registry_key_exists( key: key + "\\File Reporter" )){
		unins_key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
		for item in registry_enum_keys( key: unins_key ) {
			nfrName = registry_get_sz( key: unins_key + item, item: "DisplayName" );
			if(ContainsString( nfrName, "Novell File Reporter" )){
				nfrPath = registry_get_sz( key: unins_key + item, item: "InstallLocation" );
				if(!nfrPath){
					nfrPath = "Could not find install location";
				}
				nfrVer = registry_get_sz( key: unins_key + item, item: "DisplayVersion" );
				if(nfrVer != NULL){
					set_kb_item( name: "Novell/FileReporter/Installed", value: TRUE );
					if( ContainsString( os_arch, "x64" ) ){
						set_kb_item( name: "Novell/FileReporter64/Ver", value: nfrVer );
						register_and_report_cpe( app: "Novell File Reporter", ver: nfrVer, concluded: nfrVer, base: "cpe:/a:novell:file_reporter:x64:", expr: "^([0-9.]+)", insloc: nfrPath );
					}
					else {
						set_kb_item( name: "Novell/FileReporter/Ver", value: nfrVer );
						register_and_report_cpe( app: "Novell File Reporter", ver: nfrVer, concluded: nfrVer, base: "cpe:/a:novell:file_reporter:", expr: "^([0-9.]+)", insloc: nfrPath );
					}
				}
			}
		}
	}
}
if(registry_key_exists( key: key_iprint )){
	ver = registry_get_sz( key: key_iprint, item: "Current Version" );
	ip_key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Novell iPrint Client";
	install = registry_get_sz( key: ip_key, item: "UninstallString" );
	if( ver && install ){
		iprintVer = eregmatch( pattern: "([0-9.]+)", string: ver );
		iprintVer = iprintVer[1];
		install = install - "/uninstall";
	}
	else {
		iprintName = registry_get_sz( key: ip_key, item: "DisplayName" );
		install = registry_get_sz( key: ip_key, item: "UninstallString" );
		if(ContainsString( iprintName, "iPrint" )){
			iprintVer = eregmatch( pattern: "v([0-9.]+)", string: iprintName );
			if(iprintVer[1]){
				iprintVer = iprintVer[1];
				install = install - "/uninstall";
			}
		}
	}
	if(iprintVer){
		set_kb_item( name: "Novell/iPrint/Installed", value: TRUE );
		if( ContainsString( os_arch, "x64" ) ){
			set_kb_item( name: "Novell/iPrint64/Ver", value: iprintVer );
			register_and_report_cpe( app: "Novell iPrint Client", ver: iprintVer, concluded: iprintVer, base: "cpe:/a:novell:iprint:x64:", expr: "^([0-9.]+)", insloc: install );
		}
		else {
			set_kb_item( name: "Novell/iPrint/Ver", value: iprintVer );
			register_and_report_cpe( app: "Novell iPrint Client", ver: iprintVer, concluded: iprintVer, base: "cpe:/a:novell:iprint:", expr: "^([0-9.]+)", insloc: install );
		}
	}
}

