if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815131" );
	script_version( "2021-05-07T12:04:10+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-05-07 12:04:10 +0000 (Fri, 07 May 2021)" );
	script_tag( name: "creation_date", value: "2019-05-16 11:38:35 +0530 (Thu, 16 May 2019)" );
	script_name( "Microsoft Windows Latest Servicing Stack Updates-Defense in Depth (KB4499728)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4499728." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Microsoft has released latest servicing stack
  updates that provides enhanced security as a defense in depth measure." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to bypass a security control or take advantage of a vulnerability." );
	script_tag( name: "affected", value: "- Microsoft Windows 10 Version 1809 32-bit Systems

  - Microsoft Windows 10 Version 1809 for x64-based Systems" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4499728/windows-10-update-kb4499728" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV990001" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc", "gb_wmi_access.sc", "lsc_options.sc" );
	script_require_ports( 139, 445 );
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
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win10: 1, win10x64: 1, win2019: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
edgeVer = fetch_file_version( sysPath: sysPath, file_name: "edgehtml.dll" );
if(!edgeVer){
	exit( 0 );
}
if(IsMatchRegexp( edgeVer, "^11\\.0\\.17763" )){
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
		if(IsMatchRegexp( vers, "^10\\.0" ) && version = eregmatch( string: vers, pattern: "^([0-9.]+)" )){
			if( max_version && version_is_less_equal( version: version[1], test_version: max_version ) ){
				continue;
			}
			else {
				max_version = version[1];
				path = filePath;
			}
		}
	}
	if(max_version && version_is_less( version: max_version, test_version: "10.0.17763.503" )){
		report = report_fixed_ver( file_checked: path, file_version: max_version, vulnerable_range: "Less than 10.0.17763.503" );
		security_message( data: report );
		exit( 0 );
	}
}
exit( 99 );

