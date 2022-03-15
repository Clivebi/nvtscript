if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814270" );
	script_version( "2021-05-07T12:04:10+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-05-07 12:04:10 +0000 (Fri, 07 May 2021)" );
	script_tag( name: "creation_date", value: "2018-11-14 08:55:34 +0530 (Wed, 14 Nov 2018)" );
	script_name( "Microsoft Windows Latest Servicing Stack Updates-Defense in Depth (KB3177467)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB3177467." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Microsoft has released latest servicing stack
  updates that provides enhanced security as a defense in depth measure." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to bypass a security control or take advantage of a vulnerability." );
	script_tag( name: "affected", value: "- Microsoft Windows 7 for 32-bit/x64 Systems Service Pack 1

  - Microsoft Windows Server 2008 R2 for x64-based Systems Service Pack 1" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/3177467" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV990001" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc", "gb_wmi_access.sc", "lsc_options.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "WMI/access_successful" );
	script_exclude_keys( "win/lsc/disable_wmi_search" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("misc_func.inc.sc");
require("wmi_file.inc.sc");
require("list_array_func.inc.sc");
require("secpod_reg.inc.sc");
if(hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) <= 0){
	exit( 0 );
}
infos = kb_smb_wmi_connectinfo();
if(!infos){
	exit( 0 );
}
handle = wmi_connect( host: infos["host"], username: infos["username_wmi_smb"], password: infos["password"] );
if(!handle){
	exit( 0 );
}
fileList = wmi_file_fileversion( handle: handle, fileName: "smiengine", fileExtn: "dll", includeHeader: FALSE );
wmi_close( wmi_handle: handle );
if(!fileList || !is_array( fileList )){
	exit( 0 );
}
max_version = "";
for filePath in keys( fileList ) {
	vers = fileList[filePath];
	if(IsMatchRegexp( vers, "^6\\.1" ) && version = eregmatch( string: vers, pattern: "^([0-9.]+)" )){
		if( max_version && version_is_less_equal( version: version[1], test_version: max_version ) ){
			continue;
		}
		else {
			max_version = version[1];
			path = filePath;
		}
	}
}
if(max_version && version_is_less( version: max_version, test_version: "6.1.7601.23505" )){
	report = report_fixed_ver( file_checked: path, file_version: max_version, vulnerable_range: "Less than 6.1.7601.23505" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

