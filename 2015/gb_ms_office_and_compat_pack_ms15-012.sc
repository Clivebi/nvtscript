if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805046" );
	script_version( "2020-06-09T05:48:43+0000" );
	script_cve_id( "CVE-2015-0063", "CVE-2015-0064" );
	script_bugtraq_id( 72460, 72463 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-09 05:48:43 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2015-02-11 11:47:10 +0530 (Wed, 11 Feb 2015)" );
	script_name( "Microsoft Office Compatibility Pack Remote Code Execution Vulnerabilities (3032328)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS15-012." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Remote code execution vulnerabilities
  exists in Microsoft Compatibility Pack that is caused when Word improperly
  handles objects in memory while parsing specially crafted Office files." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code on the affected system." );
	script_tag( name: "affected", value: "Microsoft Office Compatibility Pack Service Pack 3." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/kb/3032328" );
	script_xref( name: "URL", value: "https://support.microsoft.com/kb/2956097" );
	script_xref( name: "URL", value: "https://support.microsoft.com/kb/2956098" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/security/bulletin/ms15-012" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "MS/Office/Prdts/Installed" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
cmpPckVer = get_kb_item( "SMB/Office/ComptPack/Version" );
if(cmpPckVer && IsMatchRegexp( cmpPckVer, "^12\\." )){
	xlcnvVer = get_kb_item( "SMB/Office/XLCnv/Version" );
	if(xlcnvVer && IsMatchRegexp( xlcnvVer, "^12\\." )){
		if(version_in_range( version: xlcnvVer, test_version: "12.0", test_version2: "12.0.6715.4999" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
			exit( 0 );
		}
	}
}
wordcnvVer = get_kb_item( "SMB/Office/WordCnv/Version" );
if(wordcnvVer && IsMatchRegexp( wordcnvVer, "^12\\." )){
	path = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "ProgramFilesDir" );
	if(path){
		sysVer = fetch_file_version( sysPath: path + "\\Microsoft Office\\Office12", file_name: "Wordcnv.dll" );
		if(sysVer && IsMatchRegexp( sysVer, "^12\\." )){
			if(version_in_range( version: sysVer, test_version: "12.0", test_version2: "12.0.6715.4999" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}

