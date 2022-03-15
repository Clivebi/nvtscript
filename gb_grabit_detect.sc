if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800712" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2019-11-05T16:13:01+0000" );
	script_tag( name: "last_modification", value: "2019-11-05 16:13:01 +0000 (Tue, 05 Nov 2019)" );
	script_tag( name: "creation_date", value: "2009-05-18 09:37:31 +0200 (Mon, 18 May 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Grabit Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script finds the installed Grabit Version in Windows." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "Grabit Version Detection";
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\GrabIt_is1\\";
name = registry_get_sz( key: key, item: "DisplayName" );
if(ContainsString( name, "GrabIt" )){
	grabitVer = eregmatch( pattern: "GrabIt ([0-9.]+) Beta\\ ?([0-9]+)?", string: name );
	build = eregmatch( pattern: "build ([0-9]+)", string: name );
	if( grabitVer[1] != NULL && grabitVer[2] == NULL ){
		appVer = grabitVer[1];
	}
	else {
		if(grabitVer[1] != NULL && grabitVer[2] != NULL){
			appVer = grabitVer[1] + "." + grabitVer[2];
		}
	}
	set_kb_item( name: "GrabIt/Ver", value: appVer );
	log_message( data: " version " + appVer + " was detected on the host" );
	cpe = build_cpe( value: appVer, exp: "^([0-9]\\.[0-9]+\\.[0-9]+)", base: "cpe:/a:shemes:grabit:" );
	if(!isnull( cpe )){
		register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
	}
	if(build[1] != NULL){
		set_kb_item( name: "GrabIt/Build/Ver", value: build[1] );
	}
}

