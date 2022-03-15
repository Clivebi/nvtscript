if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812984" );
	script_version( "2021-06-23T02:00:29+0000" );
	script_cve_id( "CVE-2018-0922" );
	script_bugtraq_id( 103314 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-23 02:00:29 +0000 (Wed, 23 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-03-14 10:06:49 +0530 (Wed, 14 Mar 2018)" );
	script_name( "Microsoft Office Compatibility Pack Service Pack 3 Remote Code Execution Vulnerability (KB4011720)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4011720" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error in Microsoft
  Office software when the Office software fails to properly handle objects in
  memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  who successfully exploited the vulnerability to run arbitrary code in the
  context of the current user." );
	script_tag( name: "affected", value: "Microsoft Office Compatibility Pack Service Pack 3." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4011720" );
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
cmpPckVer = get_kb_item( "SMB/Office/ComptPack/Version" );
if(cmpPckVer && IsMatchRegexp( cmpPckVer, "^12\\." )){
	wordcnvVer = get_kb_item( "SMB/Office/WordCnv/Version" );
	if(wordcnvVer && IsMatchRegexp( wordcnvVer, "^12\\." )){
		offpath = path + "\\Microsoft Office\\Office12";
		{
			sysVer = fetch_file_version( sysPath: offpath, file_name: "wordcnv.dll" );
			if(sysVer && IsMatchRegexp( sysVer, "^12\\." )){
				if(version_in_range( version: sysVer, test_version: "12.0", test_version2: "12.0.6786.4999" )){
					report = report_fixed_ver( file_checked: offpath + "\\wordcnv.dll", file_version: sysVer, vulnerable_range: "12.0 - 12.0.6786.4999" );
					security_message( data: report );
					exit( 0 );
				}
			}
		}
	}
}
exit( 0 );

