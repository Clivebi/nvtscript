if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804425" );
	script_version( "2020-06-09T08:59:39+0000" );
	script_cve_id( "CVE-2014-1757", "CVE-2014-1758", "CVE-2014-1761" );
	script_bugtraq_id( 66385, 66614, 66629 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-09 08:59:39 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2014-04-09 09:37:29 +0530 (Wed, 09 Apr 2014)" );
	script_name( "Microsoft Office Compatibility Pack Remote Code Execution Vulnerabilities (2949660)" );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS14-017." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "insight", value: "Multiple flaws are due to an error within,

  - Microsoft Word when handling certain RTF-formatted data can be exploited to
  corrupt memory.

  - Microsoft Office File Format Converter when handling certain files can be
  exploited to corrupt memory.

  - Microsoft Word when handling certain files can be exploited to cause a
  stack-based buffer overflow." );
	script_tag( name: "affected", value: "Microsoft Office Compatibility Pack Service Pack 3 and prior." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute the arbitrary
  code, cause memory corruption and compromise the system." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/kb/2878236" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/security/bulletin/ms14-017" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
			if(version_in_range( version: sysVer, test_version: "12.0", test_version2: "12.0.6695.4999" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}

