if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900647" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-05-19 08:03:45 +0200 (Tue, 19 May 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "PumpKIN TFTP Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "summary", value: "This script is detects installed version of PumpKIN TFTP." );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("smb_nt.inc.sc");
SCRIPT_DESC = "PumpKIN TFTP Version Detection";
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
pumpKINName = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" + "\\Uninstall\\PumpKIN", item: "DisplayName" );
if(pumpKINName != NULL && ContainsString( pumpKINName, "Klever PumpKIN" )){
	pumpKINVer = eregmatch( pattern: "PumpKIN ([0-9.]+)", string: pumpKINName );
	if(pumpKINVer[1] != NULL){
		set_kb_item( name: "PumpKIN/TFTP/Ver", value: pumpKINVer[1] );
		log_message( data: "PumpKIN TFTP version " + pumpKINVer[1] + " was detected on the host" );
		cpe = build_cpe( value: pumpKINVer[1], exp: "^([0-9.]+)", base: "cpe:/a:klever:pumpkin:" );
		if(!isnull( cpe )){
			register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
		}
	}
}

