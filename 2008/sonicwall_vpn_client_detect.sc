if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80044" );
	script_version( "2019-11-05T16:13:01+0000" );
	script_tag( name: "last_modification", value: "2019-11-05 16:13:01 +0000 (Tue, 05 Nov 2019)" );
	script_tag( name: "creation_date", value: "2008-10-24 20:38:19 +0200 (Fri, 24 Oct 2008)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "SonicWall Global VPN Client Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "This script is Copyright (C) 2008 Ferdy Riphagen" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "summary", value: "This script detects the installed version of
  SonicWall Global VPN Client." );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "SonicWall Global VPN Client Detection";
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\SWGVpnClient.exe";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
path = registry_get_sz( key: key, item: "Path" );
if(path){
	file = path + "\\SWGVpnClient.exe";
	version = GetVersionFromFile( file: file, verstr: "prod" );
	if(!isnull( version )){
		set_kb_item( name: "SMB/SonicWallGlobalVPNClient/Version", value: version );
		set_kb_item( name: "SMB/SonicWallGlobalVPNClient/Path", value: path );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:sonicwall:global_vpn_client:" );
		if(!isnull( cpe )){
			register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
		}
		exit( 0 );
	}
}
exit( 0 );

