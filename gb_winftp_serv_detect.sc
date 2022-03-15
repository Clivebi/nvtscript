if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800345" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2019-11-05T16:13:01+0000" );
	script_tag( name: "last_modification", value: "2019-11-05 16:13:01 +0000 (Tue, 05 Nov 2019)" );
	script_tag( name: "creation_date", value: "2009-02-04 15:43:54 +0100 (Wed, 04 Feb 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "WinFTP Server Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "Detection of WinFTP Server

This script detects the installed version of WinFTP Server." );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("smb_nt.inc.sc");
require("ftp_func.inc.sc");
require("secpod_smb_func.inc.sc");
SCRIPT_DESC = "WinFTP Server Version Detection";
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
regPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "ProgramFilesDir" );
if(!regPath){
	exit( 0 );
}
exePath = regPath + "\\WinFTP Server\\WFTPSRV.exe";
share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: exePath );
file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: exePath );
winFtpVer = GetVer( share: share, file: file );
if(winFtpVer){
	set_kb_item( name: "WinFTP/Server/Ver", value: winFtpVer );
	log_message( data: "WinFTP Server version " + winFtpVer + " running at location " + exePath + " was detected on the host" );
	cpe = build_cpe( value: winFtpVer, exp: "^([0-9.]+)", base: "cpe:/a:wftpserver:winftp_ftp_server:" );
	if(!isnull( cpe )){
		register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
	}
}

