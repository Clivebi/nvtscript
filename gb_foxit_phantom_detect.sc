if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801754" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2019-11-05T16:13:01+0000" );
	script_tag( name: "last_modification", value: "2019-11-05 16:13:01 +0000 (Tue, 05 Nov 2019)" );
	script_tag( name: "creation_date", value: "2011-03-04 14:32:35 +0100 (Fri, 04 Mar 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Foxit Phantom Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script finds the Foxit Phantom version." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "Foxit Phantom Version Detection";
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" + "\\Foxit Phantom";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
name = registry_get_sz( key: key, item: "DisplayName" );
if(ContainsString( name, "Foxit Phantom" )){
	foxitVer = registry_get_sz( key: key, item: "DisplayVersion" );
	if(foxitVer == NULL){
		exit( 0 );
	}
}
set_kb_item( name: "foxit/phantom/ver", value: foxitVer );
set_kb_item( name: "foxit/phantom_or_reader/detected", value: TRUE );
log_message( data: "Foxit Phantom version " + foxitVer + " was detected on the host" );
cpe = build_cpe( value: foxitVer, exp: "^([0-9.]+)", base: "cpe:/a:foxitsoftware:reader:" );
if(!isnull( cpe )){
	register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
}

