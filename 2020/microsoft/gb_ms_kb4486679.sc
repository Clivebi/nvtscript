if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817463" );
	script_version( "2021-08-12T06:00:50+0000" );
	script_cve_id( "CVE-2020-16933" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-12 06:00:50 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-21 16:27:00 +0000 (Wed, 21 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-10-14 11:20:23 +0530 (Wed, 14 Oct 2020)" );
	script_name( "Microsoft Word 2016 Security Feature Bypass Vulnerability(KB4486679)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4486679" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "A security feature bypass vulnerability exists
  in Microsoft Word software when it fails to properly handle .LNK files." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to perform actions in the security context of the current user." );
	script_tag( name: "affected", value: "Microsoft Word 2016." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see
  the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4486679" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/Word/Version" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
exeVer = get_kb_item( "SMB/Office/Word/Version" );
if(!exeVer){
	exit( 0 );
}
exePath = get_kb_item( "SMB/Office/Word/Install/Path" );
if(!exePath){
	exePath = "Unable to fetch the install path";
}
if(IsMatchRegexp( exeVer, "^16\\." ) && version_is_less( version: exeVer, test_version: "16.0.5071.1000" )){
	report = report_fixed_ver( file_checked: exePath + "winword.exe", file_version: exeVer, vulnerable_range: "16.0 - 16.0.5071.0999" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

