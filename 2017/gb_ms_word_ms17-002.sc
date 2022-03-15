if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809776" );
	script_version( "2021-09-08T11:01:32+0000" );
	script_cve_id( "CVE-2017-0003" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-08 11:01:32 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-12 22:15:00 +0000 (Fri, 12 Oct 2018)" );
	script_tag( name: "creation_date", value: "2017-01-11 08:33:11 +0530 (Wed, 11 Jan 2017)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Word Remote Code Execution Vulnerability (3214291)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS17-002" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists when the Office software
  fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to run arbitrary code in the context of the current user." );
	script_tag( name: "affected", value: "Microsoft Word 2016 Service Pack 1 and prior." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3128057" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/library/security/ms17-002.aspx" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
if(IsMatchRegexp( exeVer, "^(16\\.)" )){
	if(version_is_less( version: exeVer, test_version: "16.0.4483.1000" )){
		report = "File checked:     " + exePath + "winword.exe" + "\n" + "File version:     " + exeVer + "\n" + "Vulnerable range: " + "16.0 - 16.0.4483.0999" + "\n";
		security_message( data: report );
		exit( 0 );
	}
}
exit( 0 );

