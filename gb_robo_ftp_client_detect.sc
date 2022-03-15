if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801053" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2019-11-05T16:13:01+0000" );
	script_tag( name: "last_modification", value: "2019-11-05 16:13:01 +0000 (Tue, 05 Nov 2019)" );
	script_tag( name: "creation_date", value: "2009-12-02 13:54:57 +0100 (Wed, 02 Dec 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Robo-FTP Client Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script finds the installed Robo-FTP Client version." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	name = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( name, "Robo-FTP" )){
		ftpVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(!isnull( ftpVer )){
			set_kb_item( name: "Robo/FTP/Ver", value: ftpVer );
			register_and_report_cpe( app: "Robo-FTP Client", ver: ftpVer, base: "cpe:/a:robo-ftp:robo-ftp:", expr: "^([0-9.]+\\.[0-9])\\.?([a-z0-9]+)?" );
			exit( 0 );
		}
	}
}
path = registry_get_sz( key: "SOFTWARE\\Robo-FTP", item: "InstallDir" );
if(path != NULL){
	ftpVer = fetch_file_version( sysPath: path, file_name: "Robo-FTP.exe" );
	if(!isnull( ftpVer )){
		set_kb_item( name: "Robo/FTP/Ver", value: ftpVer );
		register_and_report_cpe( app: "Robo-FTP Client", ver: ftpVer, base: "cpe:/a:robo-ftp:robo-ftp:", expr: "^([0-9.]+\\.[0-9])\\.?([a-z0-9]+)?", insloc: path );
		exit( 0 );
	}
}

