if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.903404" );
	script_version( "2021-08-05T12:20:54+0000" );
	script_cve_id( "CVE-2013-3160", "CVE-2013-3847", "CVE-2013-3848", "CVE-2013-3849", "CVE-2013-3850", "CVE-2013-3851", "CVE-2013-3852", "CVE-2013-3853", "CVE-2013-3854", "CVE-2013-3855", "CVE-2013-3856", "CVE-2013-3857", "CVE-2013-3858" );
	script_bugtraq_id( 62162, 62165, 62168, 62169, 62170, 62171, 62216, 62217, 62220, 62222, 62223, 62224, 62226 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-05 12:20:54 +0000 (Thu, 05 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-09-11 17:22:16 +0530 (Wed, 11 Sep 2013)" );
	script_name( "MS Office Compatibility Pack Remote Code Execution Vulnerabilities (2845537)" );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS13-072." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "insight", value: "Multiple flaws are due to error exists when processing XML data and some
  unspecified errors." );
	script_tag( name: "affected", value: "Compatibility Pack for Microsoft Office 2007 file formats" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute the arbitrary
  code, cause memory corruption and compromise the system." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/54737" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2760823" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/security/bulletin/ms13-072" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/Office/WordCnv/Version" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
wordcnvVer = get_kb_item( "SMB/Office/WordCnv/Version" );
if(wordcnvVer && IsMatchRegexp( wordcnvVer, "^12\\." )){
	path = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "ProgramFilesDir" );
	if(path){
		sysVer = fetch_file_version( sysPath: path + "\\Microsoft Office\\Office12", file_name: "Wordcnv.dll" );
		if(sysVer){
			if(version_in_range( version: sysVer, test_version: "12.0", test_version2: "12.0.6683.5000" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}

