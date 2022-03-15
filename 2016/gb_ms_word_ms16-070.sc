if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807845" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2016-0025", "CVE-2016-3234" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-06-15 14:56:53 +0530 (Wed, 15 Jun 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Word Multiple Vulnerabilities (3163610)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Bulletin MS16-070" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple errors are due to:

  - An error in the Office software which fails to properly handle objects
    in memory.

  - An error in Microsoft Office which improperly discloses the contents of its
    memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker to execute arbitrary code on the affected system and also gain
  access to potentially sensitive information." );
	script_tag( name: "affected", value: "- Microsoft Word 2007 Service Pack 3 and prior

  - Microsoft Word 2010 Service Pack 2 and prior

  - Microsoft Word 2013 Service Pack 1 and prior

  - Microsoft Word 2016 Service Pack 1 and prior" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3115195" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3115243" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3115173" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3115182" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3163610" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-070" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/Word/Version" );
	exit( 0 );
}
require("version_func.inc.sc");
exeVer = get_kb_item( "SMB/Office/Word/Version" );
exePath = get_kb_item( "SMB/Office/Word/Install/Path" );
if(!exePath){
	exePath = "Unable to fetch the install path";
}
if(exeVer && IsMatchRegexp( exeVer, "^(12|14|15|16).*" )){
	if( IsMatchRegexp( exeVer, "^12" ) ){
		Vulnerable_range = "12 - 12.0.6749.4999";
	}
	else {
		if( IsMatchRegexp( exeVer, "^14" ) ){
			Vulnerable_range = "14 - 14.0.7170.4999";
		}
		else {
			if( IsMatchRegexp( exeVer, "^15" ) ){
				Vulnerable_range = "15 - 15.0.4833.0999";
			}
			else {
				if(IsMatchRegexp( exeVer, "^16" )){
					Vulnerable_range = "16 - 16.0.4393.0999";
				}
			}
		}
	}
	if(version_in_range( version: exeVer, test_version: "12.0", test_version2: "12.0.6749.4999" ) || version_in_range( version: exeVer, test_version: "14.0", test_version2: "14.0.7170.4999" ) || version_in_range( version: exeVer, test_version: "15.0", test_version2: "15.0.4833.0999" ) || version_in_range( version: exeVer, test_version: "16.0", test_version2: "16.0.4393.0999" )){
		report = "File checked:     " + exePath + "winword.exe" + "\n" + "File version:     " + exeVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
		security_message( data: report );
		exit( 0 );
	}
}

