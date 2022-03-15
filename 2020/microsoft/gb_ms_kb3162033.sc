if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815588" );
	script_version( "2021-08-11T12:01:46+0000" );
	script_cve_id( "CVE-2020-0760" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-11 12:01:46 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-17 19:11:00 +0000 (Fri, 17 Apr 2020)" );
	script_tag( name: "creation_date", value: "2020-04-15 09:54:48 +0530 (Wed, 15 Apr 2020)" );
	script_name( "Microsoft Publisher 2013 Remote Code Execution Vulnerability (KB3162033)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB3162033" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A remote code execution vulnerability exists
  when Microsoft Office improperly loads arbitrary type libraries." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  who successfully exploited the vulnerability could use a specially crafted file
  to perform actions in the security context of the current user." );
	script_tag( name: "affected", value: "Microsoft Publisher 2013." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/3162033" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/Publisher/Version" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
exeVer = get_kb_item( "SMB/Office/Publisher/Version" );
if(!exeVer){
	exit( 0 );
}
exePath = get_kb_item( "SMB/Office/Publisher/Installed/Path" );
if(!exePath){
	exePath = "Unable to fetch the install path";
}
if(exeVer && IsMatchRegexp( exeVer, "^15.*" )){
	if(version_in_range( version: exeVer, test_version: "15.0", test_version2: "15.0.5233.0999" )){
		report = report_fixed_ver( file_checked: exePath + "\\mspub.exe", file_version: exeVer, vulnerable_range: "15.0 - 15.0.5233.0999" );
		security_message( data: report );
		exit( 0 );
	}
}
exit( 99 );

