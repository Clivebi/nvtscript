if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900510" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-02-26 05:27:20 +0100 (Thu, 26 Feb 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "RaidenFTPD Server Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script finds the installed version of RaidenFTPD Server." );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("smb_nt.inc.sc");
require("ftp_func.inc.sc");
require("secpod_smb_func.inc.sc");
SCRIPT_DESC = "RaidenFTPD Server Version Detection";
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
exePath = registry_get_sz( key: "SYSTEM\\CurrentControlSet\\Services" + "\\RaidenFTPDService", item: "ImagePath" );
if(!exePath){
	exit( 0 );
}
exePath = exePath - "rftpdservice.exe" + "raidenftpd.exe";
share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: exePath );
file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: exePath );
rftpdVer = GetVer( file: file, share: share );
if(rftpdVer != NULL){
	set_kb_item( name: "RaidenFTPD/Ver", value: rftpdVer );
	log_message( data: "RaidenFTPD Server version " + rftpdVer + " running at" + " location " + exePath + " was detected on the host" );
	cpe = build_cpe( value: rftpdVer, exp: "^([0-9.]+)", base: "cpe:/a:raidenftpd:raidenftpd:" );
	if(!isnull( cpe )){
		register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
	}
}

