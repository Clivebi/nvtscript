if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808281" );
	script_version( "2019-07-31T09:47:07+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-31 09:47:07 +0000 (Wed, 31 Jul 2019)" );
	script_tag( name: "creation_date", value: "2016-08-03 17:52:03 +0530 (Wed, 03 Aug 2016)" );
	script_name( "Microsoft Remote Desktop Protocol Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Remote Desktop Protocol.

  The script logs in via smb and check the version of mstscax.dll file." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
rdpVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Mstscax.dll" );
if(rdpVer){
	rdpPath = sysPath + "\\System32\\Mstscax.dll";
	set_kb_item( name: "remote/desktop/protocol/Win/Installed", value: TRUE );
	set_kb_item( name: "remote/desktop/protocol/Win/Ver", value: rdpVer );
	register_and_report_cpe( app: "Microsoft Remote Desktop Protocol", ver: rdpVer, base: "cpe:/a:microsoft:rdp:", expr: "^([0-9.]+)", insloc: rdpPath );
}

