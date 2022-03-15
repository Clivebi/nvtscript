if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107630" );
	script_version( "2021-05-10T08:29:54+0000" );
	script_tag( name: "last_modification", value: "2021-05-10 08:29:54 +0000 (Mon, 10 May 2021)" );
	script_tag( name: "creation_date", value: "2019-03-30 13:50:35 +0100 (Sat, 30 Mar 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Gemalto Sentinel UltraPro 32bit Client Library Detection (Windows SMB Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc", "gb_wmi_access.sc", "gb_gemalto_sentinel_protection_installer_detect_win.sc", "lsc_options.sc" );
	script_mandatory_keys( "gemalto/sentinel_protection_installer/win/detected", "WMI/access_successful", "SMB/WindowsVersion" );
	script_exclude_keys( "win/lsc/disable_wmi_search" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "SMB login-based detection of the Gemalto Sentinel UltraPro 32bit
  Client Library." );
	script_xref( name: "URL", value: "https://sentinel.gemalto.com/" );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
if(get_kb_item( "win/lsc/disable_wmi_search" )){
	exit( 0 );
}
require("host_details.inc.sc");
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("wmi_file.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
require("cpe.inc.sc");
infos = kb_smb_wmi_connectinfo();
if(!infos){
	exit( 0 );
}
handle = wmi_connect( host: infos["host"], username: infos["username_wmi_smb"], password: infos["password"] );
if(!handle){
	exit( 0 );
}
fileList = wmi_file_file_search( handle: handle, dirPathLike: "%program files%", fileName: "ux32w", fileExtn: "dll", includeHeader: FALSE );
wmi_close( wmi_handle: handle );
if(!fileList || !is_array( fileList )){
	exit( 0 );
}
loc = fileList[0];
if(loc){
	split = split( buffer: loc, sep: "\\" );
	location = ereg_replace( string: loc, pattern: split[max_index( split ) - 1], replace: "" );
}
version = fetch_file_version( sysPath: location, file_name: "ux32w.dll" );
set_kb_item( name: "gemalto/sentinel_ultrapro_32bit_client_library/win/detected", value: TRUE );
register_and_report_cpe( app: "Gemalto Sentinel UltraPro 32bit Client Library", ver: version, concluded: loc, base: "cpe:/a:gemalto:sentinel_ultrapro_32bit_client_library:", expr: "^([0-9.]+)", insloc: location, regService: "smb-login", regPort: 0 );
exit( 0 );

