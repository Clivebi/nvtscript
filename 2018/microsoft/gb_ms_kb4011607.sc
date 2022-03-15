if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812614" );
	script_version( "2021-06-23T02:00:29+0000" );
	script_cve_id( "CVE-2018-0793", "CVE-2018-0794", "CVE-2018-0797", "CVE-2018-0798", "CVE-2018-0801", "CVE-2018-0802", "CVE-2018-0804", "CVE-2018-0805", "CVE-2018-0806", "CVE-2018-0807", "CVE-2018-0812", "CVE-2018-0845", "CVE-2018-0848", "CVE-2018-0849", "CVE-2018-0862" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-23 02:00:29 +0000 (Wed, 23 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-01-10 10:40:59 +0530 (Wed, 10 Jan 2018)" );
	script_name( "Microsoft Office Compatibility Pack Service Pack 3 Multiple RCE Vulnerabilities (KB4011607)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB4011607" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error in the way that Microsoft Outlook parses specially crafted email
    messages.

  - Multiple errors in Microsoft Office because it fails to properly handle objects in memory.

  - An error in Microsoft Office software when the Office software fails to
    properly handle RTF files." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to run arbitrary code in the context of the current user." );
	script_tag( name: "affected", value: "Microsoft Office Compatibility Pack Service Pack 3." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4011607" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/ComptPack/Version", "SMB/Office/WordCnv/Version" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
path = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "ProgramFilesDir" );
if(!path){
	exit( 0 );
}
comptpckVer = get_kb_item( "SMB/Office/ComptPack/Version" );
if(comptpckVer && IsMatchRegexp( comptpckVer, "^12\\." )){
	wordcnvVer = get_kb_item( "SMB/Office/WordCnv/Version" );
	if(wordcnvVer && IsMatchRegexp( wordcnvVer, "^12\\." )){
		offpath = path + "\\Microsoft Office\\Office12";
		sysVer = fetch_file_version( sysPath: offpath, file_name: "wordcnv.dll" );
		if(sysVer){
			if(version_in_range( version: sysVer, test_version: "12.0", test_version2: "12.0.6784.4999" )){
				report = report_fixed_ver( file_checked: offpath + "\\wordcnv.dll", file_version: sysVer, vulnerable_range: "12.0 - 12.0.6784.4999" );
				security_message( data: report );
				exit( 0 );
			}
		}
	}
}
exit( 0 );

