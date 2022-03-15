if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805541" );
	script_version( "2019-07-25T12:21:33+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-25 12:21:33 +0000 (Thu, 25 Jul 2019)" );
	script_tag( name: "creation_date", value: "2015-04-28 18:51:34 +0530 (Tue, 28 Apr 2015)" );
	script_name( "Symantec Workspace Streaming (SWS) Agent Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Symantec Workspace Streaming Agent.

  The script logs in via smb, searches for 'Symantec Workspace Streaming Agent'
  in the registry and gets the version from registry." );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	agentName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( agentName, "Symantec Workspace Streaming Agent" )){
		agentVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		agentPath = registry_get_sz( key: key + item, item: "InstallLocation" );
		if(!agentPath){
			agentPath = registry_get_sz( key: key + item, item: "InstallSource" );
			if(!agentPath){
				agentPath = "Couldn find the install location from registry";
			}
		}
		if(agentVer){
			set_kb_item( name: "Symantec/Workspace/Streaming/Agent/Win6432/Installed", value: TRUE );
			if( ContainsString( os_arch, "64" ) ){
				set_kb_item( name: "Symantec/Workspace/Streaming/Agent/Win64/Ver", value: agentVer );
				register_and_report_cpe( app: agentName, ver: agentVer, base: "cpe:/a:symantec:workspace_streaming:x64:", expr: "^([0-9.]+)", insloc: agentPath );
			}
			else {
				set_kb_item( name: "Symantec/Workspace/Streaming/Agent/Win/Ver", value: agentVer );
				register_and_report_cpe( app: agentName, ver: agentVer, base: "cpe:/a:symantec:workspace_streaming:", expr: "^([0-9.]+)", insloc: agentPath );
			}
		}
		exit( 0 );
	}
}

