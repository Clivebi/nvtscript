if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805011" );
	script_version( "2020-06-09T08:59:39+0000" );
	script_cve_id( "CVE-2014-6333", "CVE-2014-6334", "CVE-2014-6335" );
	script_bugtraq_id( 70961, 70962, 70963 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-09 08:59:39 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2014-11-12 08:48:45 +0530 (Wed, 12 Nov 2014)" );
	script_name( "MS Office Compatibility Pack Remote Code Execution Vulnerabilities (3009710)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS14-069." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaws are due to errors when parsing
  files." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute the arbitrary code, cause memory corruption and
  compromise the system." );
	script_tag( name: "affected", value: "Microsoft Office Compatibility Pack SP3 and prior." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://support.microsoft.com/kb/2899526" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS14-069" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/WordCnv/Version" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
wordcnvVer = get_kb_item( "SMB/Office/WordCnv/Version" );
if(wordcnvVer && IsMatchRegexp( wordcnvVer, "^12.*" )){
	path = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "ProgramFilesDir" );
	if(path){
		sysVer = fetch_file_version( sysPath: path + "\\Microsoft Office\\Office12", file_name: "Wordcnv.dll" );
		if(sysVer){
			if(version_in_range( version: sysVer, test_version: "12.0", test_version2: "12.0.6707.4999" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}

