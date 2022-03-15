if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800329" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2019-11-05T16:13:01+0000" );
	script_tag( name: "last_modification", value: "2019-11-05 16:13:01 +0000 (Tue, 05 Nov 2019)" );
	script_tag( name: "creation_date", value: "2009-01-06 15:38:06 +0100 (Tue, 06 Jan 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "BulletProof FTP Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script finds the installed BulletProof FTP Version." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "BulletProof FTP Version Detection";
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" + "\\BulletProof FTP Client_is1";
if(ContainsString( registry_get_sz( key: key, item: "DisplayName" ), "BulletProof FTP Client" )){
	exePath = registry_get_sz( key: key, item: "DisplayIcon" );
	if(!exePath){
		exit( 0 );
	}
	share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: exePath );
	file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: exePath );
	bpftpVer = GetVer( file: file, share: share );
	if(bpftpVer){
		set_kb_item( name: "BulletProof/Client/Ver", value: bpftpVer );
		log_message( data: "Bullet Proof FTP Client version " + bpftpVer + " running" + " at location " + exePath + " was detected on the host" );
		cpe = build_cpe( value: bpftpVer, exp: "^([0-9.]+)", base: "cpe:/a:bpftp:bulletproof_ftp_client:" );
		if(!isnull( cpe )){
			register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
		}
	}
}

