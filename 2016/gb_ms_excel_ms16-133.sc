if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809716" );
	script_version( "2020-06-08T14:40:48+0000" );
	script_cve_id( "CVE-2016-7213", "CVE-2016-7228", "CVE-2016-7229", "CVE-2016-7231", "CVE-2016-7236" );
	script_bugtraq_id( 93993, 93994, 93995, 93996, 94025 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-08 14:40:48 +0000 (Mon, 08 Jun 2020)" );
	script_tag( name: "creation_date", value: "2016-11-09 10:02:12 +0530 (Wed, 09 Nov 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Excel Multiple RCE Vulnerabilities (3199168)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS16-133." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist as Office software
  fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user." );
	script_tag( name: "affected", value: "- Microsoft Excel 2007 Service Pack 3

  - Microsoft Excel 2010 Service Pack 2

  - Microsoft Excel 2013 Service Pack 1

  - Microsoft Excel 2016 Service Pack 1" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3118395" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3118390" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3127904" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3127921" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-133" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/Excel/Version" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
excelVer = get_kb_item( "SMB/Office/Excel/Version" );
if(!excelVer){
	exit( 0 );
}
excelPath = get_kb_item( "SMB/Office/Excel/Install/Path" );
if(!excelPath){
	excelPath = "Unable to fetch the install path";
}
if(IsMatchRegexp( excelVer, "^(12|14|15|16)\\..*" )){
	if( IsMatchRegexp( excelVer, "^12" ) ){
		Vulnerable_range = "12 - 12.0.6759.4999";
	}
	else {
		if( IsMatchRegexp( excelVer, "^14" ) ){
			Vulnerable_range = "14 - 14.0.7176.4999";
		}
		else {
			if( IsMatchRegexp( excelVer, "^15" ) ){
				Vulnerable_range = "15 - 15.0.4875.0999";
			}
			else {
				if(IsMatchRegexp( excelVer, "^16" )){
					Vulnerable_range = "16 - 16.0.4456.1002";
				}
			}
		}
	}
	if(version_in_range( version: excelVer, test_version: "12.0", test_version2: "12.0.6759.4999" ) || version_in_range( version: excelVer, test_version: "14.0", test_version2: "14.0.7176.4999" ) || version_in_range( version: excelVer, test_version: "15.0", test_version2: "15.0.4875.0999" ) || version_in_range( version: excelVer, test_version: "16.0", test_version2: "16.0.4456.1002" )){
		report = "File checked:     " + excelPath + "Excel.exe" + "\n" + "File version:     " + excelVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
		security_message( data: report );
		exit( 0 );
	}
}

