if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900976" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-11-20 06:52:52 +0100 (Fri, 20 Nov 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "COWON Media Center JetAudio Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script detects the installed version of COWON Media
  Center JetAudio." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "COWON Media Center JetAudio Version Detection";
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\COWON\\Jet-Audio" )){
	exit( 0 );
}
jaPath = registry_get_sz( key: "SOFTWARE\\COWON\\Jet-Audio", item: "InstallPath_Main" );
if(jaPath == NULL){
	jaPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" + "\\App Paths\\JetAudio.exe", item: "Path" );
	if(jaPath == NULL){
		exit( 0 );
	}
}
share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: jaPath );
file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: jaPath + "\\JetAudio.exe" );
jaVer = GetVer( file: file, share: share );
if(jaVer != NULL){
	set_kb_item( name: "JetAudio/Ver", value: jaVer );
	log_message( data: "COWON Media Center JetAudio version " + jaVer + " running at location " + jaPath + " was detected on the host" );
	cpe = build_cpe( value: jaVer, exp: "^([0-9.]+)", base: "cpe:/a:cowonamerica:cowon_media_center-jetaudio:" );
	if(!isnull( cpe )){
		register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
	}
}

