if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817099" );
	script_version( "2021-08-11T09:52:23+0000" );
	script_cve_id( "CVE-2020-1583", "CVE-2020-1503" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-11 09:52:23 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 19:03:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-08-12 10:00:41 +0530 (Wed, 12 Aug 2020)" );
	script_name( "Microsoft Word 2010 Service Pack 2 Multiple Remote Code Execution Vulnerabilities (KB4484494)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4484494" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple information disclosure vulnerabilities exist
  when Microsoft Word improperly discloses the contents of its memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to disclose the information to compromise the user's computer or data." );
	script_tag( name: "affected", value: "Microsoft Word 2010 Service Pack 2." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see
  the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4484494" );
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
if(!exeVer = get_kb_item( "SMB/Office/Word/Version" )){
	exit( 0 );
}
if(!exePath = get_kb_item( "SMB/Office/Word/Install/Path" )){
	exePath = "Unable to fetch the install path";
}
if(IsMatchRegexp( exeVer, "^14\\." ) && version_is_less( version: exeVer, test_version: "14.0.7256.5000" )){
	report = report_fixed_ver( file_checked: exePath + "winword.exe", file_version: exeVer, vulnerable_range: "14.0 - 14.0.7256.4999" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

