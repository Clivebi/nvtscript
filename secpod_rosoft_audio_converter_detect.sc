if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902078" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-06-22 14:43:46 +0200 (Tue, 22 Jun 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Rosoft Audio Converter Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This host is installed with Rosoft Audio Converter." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "Rosoft Audio Converter Version Detection";
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	racName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( racName, "Rosoft Audio Converter, Silver Edition, Release" )){
		racPath = registry_get_sz( key: key + item, item: "InstallLocation" );
		racVer = eregmatch( pattern: "Release, ([0-9.]+)", string: racName );
		if(racVer[1] != NULL){
			set_kb_item( name: "Rosoft/Audio/Converter/Ver", value: racVer[1] );
			log_message( data: "Rosoft Audio Converter version " + racVer[1] + " running at location " + racPath + " was detected on the host" );
			cpe = build_cpe( value: racVer[1], exp: "^([0-9.]+)", base: "cpe:/a:rosoftengineering:rosoft_audio_converter:" );
			if(!isnull( cpe )){
				register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
			}
		}
	}
}

