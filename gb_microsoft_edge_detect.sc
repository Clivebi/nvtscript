if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806184" );
	script_version( "2019-07-31T09:47:07+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-31 09:47:07 +0000 (Wed, 31 Jul 2019)" );
	script_tag( name: "creation_date", value: "2016-01-04 15:07:42 +0530 (Mon, 04 Jan 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Edge Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of Microsoft Edge.

The script logs in via smb, detects the version of Microsoft Edge
on remote host and sets the KB." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc", "smb_registry_access.sc" );
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
sysPath = sysPath + "\\SystemApps\\Microsoft.MicrosoftEdge_8wekyb3d8bbwe";
file = "MicrosoftEdge.exe";
ver = fetch_file_version( sysPath: sysPath, file_name: file );
if(ver != NULL){
	set_kb_item( name: "MS/Edge/Version", value: ver );
	set_kb_item( name: "MS/Edge/Installed", value: TRUE );
	set_kb_item( name: "MS/IE_or_EDGE/Installed", value: TRUE );
	register_and_report_cpe( app: "Microsoft Edge", ver: ver, base: "cpe:/a:microsoft:edge:", expr: "^([0-9.]+)", insloc: sysPath );
}

