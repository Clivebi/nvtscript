if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800579" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2019-11-05T16:13:01+0000" );
	script_tag( name: "last_modification", value: "2019-11-05 16:13:01 +0000 (Tue, 05 Nov 2019)" );
	script_tag( name: "creation_date", value: "2009-06-09 08:37:33 +0200 (Tue, 09 Jun 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Xvid Version Detection (Windows)" );
	script_family( "Product detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script retrieves Xvid version for Windows." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "Xvid Version Detection (Windows)";
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	xvidName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(IsMatchRegexp( xvidName, "Xvi[D|d]" )){
		xvidVer = eregmatch( pattern: "Xvi[d|D].*([0-9]\\.[0-9]\\.[0-9]+)", string: xvidName );
		if(xvidVer[1] != NULL){
			set_kb_item( name: "Xvid/Win/Ver", value: xvidVer[1] );
			log_message( data: "Xvid version " + xvidVer[1] + " was detected on the host" );
			cpe = build_cpe( value: xvidVer[1], exp: "^([0-9.]+)", base: "cpe:/a:xvid:xvid:" );
			if(!isnull( cpe )){
				register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
			}
		}
		exit( 0 );
	}
}

