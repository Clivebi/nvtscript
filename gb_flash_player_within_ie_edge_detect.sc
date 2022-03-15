if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810611" );
	script_version( "2021-02-08T13:19:59+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-02-08 13:19:59 +0000 (Mon, 08 Feb 2021)" );
	script_tag( name: "creation_date", value: "2017-03-10 12:18:44 +0530 (Fri, 10 Mar 2017)" );
	script_name( "Adobe Flash Player Within Microsoft IE and Edge Detection (Windows SMB Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_ms_ie_detect.sc", "gb_microsoft_edge_detect.sc" );
	script_mandatory_keys( "MS/IE_or_EDGE/Installed" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "SMB login-based detection of Adobe Flash Player within Microsoft
  Internet Explorer (IE) and Edge." );
	script_tag( name: "qod_type", value: "executable_version" );
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
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ){
	fileVer = fetch_file_version( sysPath: sysPath, file_name: "System32\\Flashplayerapp.exe" );
	insloc = sysPath + "\\System32";
}
else {
	if(ContainsString( os_arch, "x64" )){
		fileVer = fetch_file_version( sysPath: sysPath, file_name: "SysWOW64\\Flashplayerapp.exe" );
		insloc = sysPath + "\\SysWOW64";
	}
}
if(!fileVer){
	exit( 0 );
}
ie = get_kb_item( "MS/IE/Installed" );
if( ie ){
	set_kb_item( name: "adobe/flash_player/detected", value: TRUE );
	set_kb_item( name: "AdobeFlashPlayer/IE/Ver", value: fileVer );
	set_kb_item( name: "AdobeFlash/IE_or_EDGE/Installed", value: TRUE );
	base_cpe = "cpe:/a:adobe:flash_player_internet_explorer";
}
else {
	edge = get_kb_item( "MS/Edge/Installed" );
	if(edge){
		set_kb_item( name: "adobe/flash_player/detected", value: TRUE );
		set_kb_item( name: "AdobeFlashPlayer/EDGE/Ver", value: fileVer );
		set_kb_item( name: "AdobeFlash/IE_or_EDGE/Installed", value: TRUE );
		base_cpe = "cpe:/a:adobe:flash_player_edge";
	}
}
cpe = build_cpe( value: fileVer, exp: "^([0-9.]+)", base: base_cpe + ":" );
if(!cpe){
	cpe = base_cpe;
}
register_product( cpe: cpe, location: insloc, port: 0, service: "smb-login" );
log_message( data: build_detection_report( app: "Adobe Flash Player within IE/Edge", version: fileVer, install: insloc, cpe: cpe, concluded: fileVer ) );
exit( 0 );

