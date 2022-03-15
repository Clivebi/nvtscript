if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900930" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-09-16 15:34:19 +0200 (Wed, 16 Sep 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "SolarWinds TFTP Server Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script detects installed version of SolarWinds TFTP Server." );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
SCRIPT_DESC = "SolarWinds TFTP Server Version Detection";
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
stftpKey = "SOFTWARE\\";
for item in registry_enum_keys( key: stftpKey ) {
	if(ContainsString( item, "SolarWinds" )){
		stftpPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "ProgramFilesDir" );
		if(stftpPath != NULL){
			share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: stftpPath );
			file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: stftpPath + "\\SolarWinds\\TFTPServer\\TFTPServer.exe" );
			stftpVer = GetVer( share: share, file: file );
			if(isnull( stftpVer )){
				file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: stftpPath + "\\SolarWinds\\Free Tools\\TFTP-Server.exe" );
				stftpVer = GetVer( share: share, file: file );
			}
			if(stftpVer){
				set_kb_item( name: "SolarWinds/TFTP/Ver", value: stftpVer );
				log_message( data: "SolarWinds TFTP Server version " + stftpVer + " was detected on the host" );
				cpe = build_cpe( value: stftpVer, exp: "^([0-9.]+)", base: "cpe:/a:solarwinds:tftp_server:" );
				if(!isnull( cpe )){
					register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
				}
			}
		}
	}
}

