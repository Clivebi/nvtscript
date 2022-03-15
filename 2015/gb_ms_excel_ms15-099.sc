if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806110" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2015-2520", "CVE-2015-2521", "CVE-2015-2523" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-09-09 10:36:45 +0530 (Wed, 09 Sep 2015)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Excel Multiple Remote Code Execution Vulnerabilities (3089664)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Bulletin MS15-099." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist when,

  - Microsoft Excel improperly handles the loading of dynamic link library
    (DLL) files.

  - Error when memory is released in an unintended manner.

  - Improper handling of files in the memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user and
  to perform actions in the security context of the current user." );
	script_tag( name: "affected", value: "- Microsoft Excel 2007 Service Pack 3 and prior

  - Microsoft Excel 2010 Service Pack 2 and prior

  - Microsoft Excel 2013 Service Pack 1 and prior" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3089664" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/library/security/MS15-099" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/Excel/Version" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/security/bulletin/ms15-099" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
excelVer = get_kb_item( "SMB/Office/Excel/Version" );
if(IsMatchRegexp( excelVer, "^(12|14|15)\\..*" )){
	if( IsMatchRegexp( excelVer, "^12" ) ){
		Vulnerable_range = "12 - 12.0.6729.4999";
	}
	else {
		if( IsMatchRegexp( excelVer, "^14" ) ){
			Vulnerable_range = "14 - 14.0.7157.4999";
		}
		else {
			if(IsMatchRegexp( excelVer, "^15" )){
				Vulnerable_range = "15 - 15.0.4753.0999";
			}
		}
	}
	if(version_in_range( version: excelVer, test_version: "12.0", test_version2: "12.0.6729.4999" ) || version_in_range( version: excelVer, test_version: "14.0", test_version2: "14.0.7157.4999" ) || version_in_range( version: excelVer, test_version: "15.0", test_version2: "15.0.4753.0999" )){
		report = "File checked:  Excel.exe" + "\n" + "File version:     " + excelVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
		security_message( data: report );
		exit( 0 );
	}
}
