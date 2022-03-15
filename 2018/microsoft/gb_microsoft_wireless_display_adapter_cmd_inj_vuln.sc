if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813702" );
	script_version( "2021-06-23T02:00:29+0000" );
	script_cve_id( "CVE-2018-8306" );
	script_tag( name: "cvss_base", value: "5.2" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-23 02:00:29 +0000 (Wed, 23 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-07-17 15:16:38 +0530 (Tue, 17 Jul 2018)" );
	script_name( "Microsoft Wireless Display Adapter Command Injection Vulnerability" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Advisory for CVE-2018-8306." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error when the
  Microsoft Wireless Display Adapter does not properly manage user input." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to send administrative commands to the MWDA, including commands with illegal
  characters which could cause the MWDA to stop functioning correctly." );
	script_tag( name: "affected", value: "Microsoft Wireless Display Adapter V2 Software Version 2.0.8350, 2.0.8365 and 2.0.8372." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8306" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "smb_reg_service_pack.sc", "gb_wmi_access.sc", "lsc_options.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "WMI/access_successful" );
	script_require_ports( 139, 445 );
	script_exclude_keys( "win/lsc/disable_wmi_search" );
	exit( 0 );
}
require("secpod_reg.inc.sc");
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("misc_func.inc.sc");
require("wmi_file.inc.sc");
require("list_array_func.inc.sc");
if(hotfix_check_sp( win10: 1, win10x64: 1 ) <= 0){
	exit( 0 );
}
storelocation = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Appx", item: "PackageRoot" );
if(!storelocation){
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
fileList = wmi_file_fileversion( handle: handle, dirPathLike: "%wirelessdisplayadapter%", fileName: "wirelessdisplayadapter", fileExtn: "dll", includeHeader: FALSE );
wmi_close( wmi_handle: handle );
if(!fileList || !is_array( fileList )){
	exit( 0 );
}
report = "";
for filePath in keys( fileList ) {
	if(!ContainsString( filePath, storelocation ) && !ContainsString( filePath, tolower( storelocation ) )){
		continue;
	}
	vers = fileList[filePath];
	if(vers && version = eregmatch( string: vers, pattern: "^([0-9.]+)" )){
		if(version_is_less( version: version[1], test_version: "3.0.124.0" )){
			VULN = TRUE;
			report += report_fixed_ver( file_version: version[1], file_checked: filePath, fixed_version: "3.0.124.0" ) + "\n";
		}
	}
}
if(VULN){
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

