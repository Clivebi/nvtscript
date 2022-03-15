CPE = "cpe:/a:microsoft:frontpage";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.903321" );
	script_version( "2021-08-05T12:20:54+0000" );
	script_cve_id( "CVE-2013-3137" );
	script_bugtraq_id( 62185 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-05 12:20:54 +0000 (Thu, 05 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-09-11 11:12:46 +0530 (Wed, 11 Sep 2013)" );
	script_name( "Microsoft FrontPage Information Disclosure Vulnerability (2825621)" );
	script_tag( name: "summary", value: "This host is missing an important security update according to Microsoft
  Bulletin MS13-078." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "insight", value: "Flaw is due to an unspecified information disclosure vulnerability." );
	script_tag( name: "affected", value: "Microsoft FrontPage 2003 Service Pack 3." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to disclose the contents
  of a file on a target system." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2825621" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-078" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_ms_frontpage_detect.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "Microsoft/FrontPage/Ver" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("host_details.inc.sc");
require("secpod_smb_func.inc.sc");
appPath = get_app_location( cpe: CPE, skip_port: TRUE );
if(appPath && !ContainsString( appPath, "Unable to find the install" )){
	pageVer = fetch_file_version( sysPath: appPath, file_name: "Frontpg.exe" );
	if(!pageVer){
		exit( 0 );
	}
	if(version_in_range( version: pageVer, test_version: "11.0", test_version2: "11.0.8338" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

