if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806899" );
	script_version( "2020-06-08T14:40:48+0000" );
	script_cve_id( "CVE-2016-0021", "CVE-2016-0057", "CVE-2016-0134" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-08 14:40:48 +0000 (Mon, 08 Jun 2020)" );
	script_tag( name: "creation_date", value: "2016-03-09 13:44:08 +0530 (Wed, 09 Mar 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Word Remote Code Execution Vulnerabilities (3141806)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS16-029" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist as Office software fails
  to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user." );
	script_tag( name: "affected", value: "- Microsoft Word 2007 Service Pack 3 and prior

  - Microsoft Word 2010 Service Pack 2 and prior

  - Microsoft Word 2013 Service Pack 1 and prior

  - Microsoft Word 2016 Service Pack 1 and prior" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3114901" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3114878" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3114824" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/library/security/MS16-029" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/Word/Version" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/security/bulletin/ms16-029" );
	exit( 0 );
}
require("version_func.inc.sc");
exeVer = get_kb_item( "SMB/Office/Word/Version" );
if(!exeVer){
	exit( 0 );
}
exePath = get_kb_item( "SMB/Office/Word/Install/Path" );
if(!exePath){
	exePath = "Unable to fetch the install path";
}
if(exeVer && IsMatchRegexp( exeVer, "^(12|14|15|16).*" )){
	if( IsMatchRegexp( exeVer, "^12" ) ){
		Vulnerable_range = "12 - 12.0.6745.4999";
	}
	else {
		if( IsMatchRegexp( exeVer, "^14" ) ){
			Vulnerable_range = "14 - 14.0.7167.5000";
		}
		else {
			if( IsMatchRegexp( exeVer, "^15" ) ){
				Vulnerable_range = "15 - 15.0.4805.1000";
			}
			else {
				if(IsMatchRegexp( exeVer, "^16" )){
					Vulnerable_range = "16 - 16.0.4351.1000";
				}
			}
		}
	}
	if(version_in_range( version: exeVer, test_version: "12.0", test_version2: "12.0.6745.4999" ) || version_in_range( version: exeVer, test_version: "14.0", test_version2: "14.0.7167.5000" ) || version_in_range( version: exeVer, test_version: "15.0", test_version2: "15.0.4805.1000" ) || version_in_range( version: exeVer, test_version: "16.0", test_version2: "16.0.4351.1000" )){
		report = "File checked:     " + exePath + "winword.exe" + "\n" + "File version:     " + exeVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
		security_message( data: report );
		exit( 0 );
	}
}

