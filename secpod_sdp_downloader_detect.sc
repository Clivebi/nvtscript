if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900641" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-05-20 10:26:22 +0200 (Wed, 20 May 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "SDP Downloader Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script detects the installed version of SDP Downloader." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "SDP Downloader Version Detection";
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
sdpKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: sdpKey )){
	exit( 0 );
}
for item in registry_enum_keys( key: sdpKey ) {
	sdpName = registry_get_sz( key: sdpKey + item, item: "DisplayName" );
	if(ContainsString( sdpName, "SDP Downloader" )){
		sdpVer = registry_get_sz( key: sdpKey + item, item: "DisplayVersion" );
		if(sdpVer){
			set_kb_item( name: "SDP/Downloader/Ver", value: sdpVer );
			log_message( data: "SDP Downloader version " + sdpVer + " was detected on the host" );
			cpe = build_cpe( value: sdpVer, exp: "^([0-9.]+)", base: "cpe:/a:sdp_multimedia:streaming_download_project:" );
			if(!isnull( cpe )){
				register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
			}
		}
		exit( 0 );
	}
}

