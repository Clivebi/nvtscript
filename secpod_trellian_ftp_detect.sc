if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901108" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-04-29 10:04:32 +0200 (Thu, 29 Apr 2010)" );
	script_name( "Trellian FTP Version Detection" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script finds the installed Trellian FTP version." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "Trellian FTP Version Detection";
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\TRELLIAN\\Trellian FTP" )){
	exit( 0 );
}
trellianPath = registry_get_sz( key: "SOFTWARE\\TRELLIAN\\LiveUpgrade\\Components" + "\\Trellian FTP", item: "path" );
if(!trellianPath){
	exit( 0 );
}
share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: trellianPath );
file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: trellianPath );
trellianVer = GetVer( share: share, file: file );
if(trellianVer){
	set_kb_item( name: "TrellianFTP/Version", value: trellianVer );
	log_message( data: "Trellian FTP version " + trellianVer + " running at " + "location " + trellianPath + " was detected on the host" );
	cpe = build_cpe( value: trellianVer, exp: "^([0-9.]+)", base: "cpe:/a:trellian:ftp:" );
	if(!isnull( cpe )){
		register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
	}
}

