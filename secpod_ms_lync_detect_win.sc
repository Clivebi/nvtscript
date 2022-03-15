if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902843" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2012-06-13 12:12:12 +0530 (Wed, 13 Jun 2012)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Microsoft Lync Version Detection" );
	script_tag( name: "summary", value: "Detects the installed version of Microsoft Lync.

The script logs in via smb, searches for Microsoft Lync in the registry and
gets the version from 'DisplayVersion' string in registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("cpe.inc.sc");
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
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		lyncName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(( ContainsString( lyncName, "Microsoft Office Communicator" ) || ContainsString( lyncName, "Microsoft Lync" ) ) && !ContainsString( lyncName, "Lync Server" )){
			ver = registry_get_sz( key: key + item, item: "DisplayVersion" );
			if(ver){
				path = registry_get_sz( key: key + item, item: "InstallLocation" );
				if(!path){
					path = "Could not find the install path from registry";
				}
				rlsVer = eregmatch( pattern: "[0-9]+", string: lyncName );
				if( ContainsString( lyncName, "Attendant" ) ){
					set_kb_item( name: "MS/Lync/Attendant/path", value: path );
					set_kb_item( name: "MS/Lync/Installed", value: TRUE );
					set_kb_item( name: "MS/Lync/Attendant6432/Installed", value: TRUE );
					if( ContainsString( os_arch, "32" ) || ContainsString( key, "Wow6432Node" ) ){
						set_kb_item( name: "MS/Lync/Attendant/Ver", value: ver );
						register_and_report_cpe( app: lyncName, ver: ver, concluded: ver, base: "cpe:/a:microsoft:lync:" + rlsVer[0] + "::attendant_x86:", expr: "^([0-9.]+)", insloc: path );
					}
					else {
						if(ContainsString( os_arch, "64" ) && !ContainsString( key, "Wow6432Node" )){
							set_kb_item( name: "MS/Lync/Attendant64/Ver", value: ver );
							register_and_report_cpe( app: lyncName, ver: ver, concluded: ver, base: "cpe:/a:microsoft:lync:" + rlsVer[0] + "::attendant_x64:", expr: "^([0-9.]+)", insloc: path );
						}
					}
				}
				else {
					if( ContainsString( lyncName, "Attendee" ) ){
						set_kb_item( name: "MS/Lync/Attendee/Ver", value: ver );
						set_kb_item( name: "MS/Lync/Attendee/path", value: path );
						set_kb_item( name: "MS/Lync/Installed", value: TRUE );
						register_and_report_cpe( app: lyncName, ver: ver, concluded: ver, base: "cpe:/a:microsoft:lync:" + rlsVer[0] + "::attendee:", expr: "^([0-9.]+)", insloc: path );
					}
					else {
						if( ContainsString( lyncName, "Microsoft Office Communicator" ) ){
							set_kb_item( name: "MS/Office/Communicator/path", value: path );
							set_kb_item( name: "MS/Office/Communicator6432/Installed", value: TRUE );
							if( ContainsString( os_arch, "64" ) && !ContainsString( key, "Wow6432Node" ) ){
								set_kb_item( name: "MS/Office/Communicator64/Ver", value: ver );
								register_and_report_cpe( app: lyncName, ver: ver, concluded: ver, base: "cpe:/a:microsoft:office_communicator:" + rlsVer[0] + ":x64:", expr: "^([0-9.]+)", insloc: path );
							}
							else {
								set_kb_item( name: "MS/Office/Communicator/Ver", value: ver );
								register_and_report_cpe( app: lyncName, ver: ver, concluded: ver, base: "cpe:/a:microsoft:office_communicator:" + rlsVer[0] + ":", expr: "^([0-9.]+)", insloc: path );
							}
						}
						else {
							if( ContainsString( lyncName, "Lync Basic" ) ){
								set_kb_item( name: "MS/Lync/Basic/path", value: path );
								set_kb_item( name: "MS/Lync/Installed", value: TRUE );
								set_kb_item( name: "MS/Lync/Basic6432/Installed", value: TRUE );
								if( ContainsString( os_arch, "64" ) && !ContainsString( key, "Wow6432Node" ) ){
									set_kb_item( name: "MS/Lync/Basic64/Ver", value: ver );
									register_and_report_cpe( app: lyncName, ver: ver, concluded: ver, base: "cpe:/a:microsoft:lync_basic:" + rlsVer[0] + "::x64:", expr: "^([0-9.]+)", insloc: path );
								}
								else {
									if( ContainsString( os_arch, "32" ) || ContainsString( key, "Wow6432Node" ) ){
										set_kb_item( name: "MS/Lync/Basic/Ver", value: ver );
										register_and_report_cpe( app: lyncName, ver: ver, concluded: ver, base: "cpe:/a:microsoft:lync_basic:" + rlsVer[0] + "::x86:", expr: "^([0-9.]+)", insloc: path );
									}
									else {
										set_kb_item( name: "MS/Lync/Basic/Ver", value: ver );
										register_and_report_cpe( app: lyncName, ver: ver, concluded: ver, base: "cpe:/a:microsoft:lync_basic:" + rlsVer[0] + ":", expr: "^([0-9.]+)", insloc: path );
									}
								}
							}
							else {
								set_kb_item( name: "MS/Lync/path", value: path );
								set_kb_item( name: "MS/Lync/Installed", value: TRUE );
								set_kb_item( name: "MS/Lync6432/Installed", value: TRUE );
								if( ContainsString( os_arch, "64" ) && !ContainsString( key, "Wow6432Node" ) ){
									set_kb_item( name: "MS/Lync64/Ver", value: ver );
									register_and_report_cpe( app: lyncName, ver: ver, concluded: ver, base: "cpe:/a:microsoft:lync:" + rlsVer[0] + "::x64:", expr: "^([0-9.]+)", insloc: path );
								}
								else {
									if( ContainsString( os_arch, "32" ) || ContainsString( key, "Wow6432Node" ) ){
										set_kb_item( name: "MS/Lync/Ver", value: ver );
										register_and_report_cpe( app: lyncName, ver: ver, concluded: ver, base: "cpe:/a:microsoft:lync:" + rlsVer[0] + "::x86:", expr: "^([0-9.]+)", insloc: path );
									}
									else {
										set_kb_item( name: "MS/Lync/Ver", value: ver );
										register_and_report_cpe( app: lyncName, ver: ver, concluded: ver, base: "cpe:/a:microsoft:lync:" + rlsVer[0] + ":", expr: "^([0-9.]+)", insloc: path );
									}
								}
							}
						}
					}
				}
			}
		}
	}
}

