if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810907" );
	script_version( "2021-09-14T11:01:46+0000" );
	script_cve_id( "CVE-2017-8543", "CVE-2017-8544" );
	script_bugtraq_id( 98824, 98826 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-14 11:01:46 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-07-05 16:51:57 +0530 (Wed, 05 Jul 2017)" );
	script_name( "Microsoft Windows Search Multiple Vulnerabilities (KB4024402)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc", "gb_wmi_access.sc", "lsc_options.sc" );
	script_mandatory_keys( "WMI/access_successful", "SMB/WindowsVersion" );
	script_exclude_keys( "win/lsc/disable_wmi_search" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4024402" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB4024402." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist because Windows Search
  improperly handles objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  an attacker to take control of the affected system. An attacker could then:

  - install programs

  - view, change, or delete data

  - create new accounts with full user rights and obtain sensitive information." );
	script_tag( name: "affected", value: "Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("misc_func.inc.sc");
require("wmi_file.inc.sc");
require("list_array_func.inc.sc");
if(hotfix_check_sp( win2008: 3, win2008x64: 3 ) <= 0){
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
fileList = wmi_file_fileversion( handle: handle, dirPathLike: "%windowssearchengine%", fileName: "tquery", fileExtn: "dll", includeHeader: FALSE );
wmi_close( wmi_handle: handle );
if(!fileList || !is_array( fileList )){
	exit( 0 );
}
maxVer = "";
for filePath in keys( fileList ) {
	vers = fileList[filePath];
	if(vers && version = eregmatch( string: vers, pattern: "^([0-9.]+)" )){
		if( maxVer && version_is_less( version: version[1], test_version: maxVer ) ){
			continue;
		}
		else {
			foundMax = TRUE;
			maxVer = version[1];
			maxPath = filePath;
		}
	}
}
if(foundMax){
	if( version_is_less( version: maxVer, test_version: "7.0.6002.19806" ) ){
		Vulnerable_range = "Less than 7.0.6002.19806";
	}
	else {
		if(version_in_range( version: maxVer, test_version: "7.0.6002.23000", test_version2: "7.0.6002.24125" )){
			Vulnerable_range = "7.0.6002.23000 - 7.0.6002.24125";
		}
	}
	if(Vulnerable_range){
		report = report_fixed_ver( file_version: maxVer, file_checked: maxPath, vulnerable_range: Vulnerable_range );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

