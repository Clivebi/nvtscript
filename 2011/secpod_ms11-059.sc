if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900294" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-08-11 06:41:03 +0200 (Thu, 11 Aug 2011)" );
	script_bugtraq_id( 49026 );
	script_cve_id( "CVE-2011-1975" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Microsoft Data Access Components Remote Code Execution Vulnerabilities (2560656)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2560656" );
	script_xref( name: "URL", value: "http://www.sophos.com/support/knowledgebase/article/113981.html" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-059" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attacker to execute arbitrary code
  by tricking a user into opening a Microsoft Excel file (.xlsx) located on a
  remote WebDAV or SMB share." );
	script_tag( name: "affected", value: "Microsoft Windows 7 Service Pack 1 and prior." );
	script_tag( name: "insight", value: "The flaws are due when the Windows Data Access Tracing component incorrectly
  restricts the path used for loading external libraries." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS11-059." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win7: 2 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "2560656" ) == 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
sysVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Odbcjt32.dll" );
if(!sysVer){
	exit( 0 );
}
if(hotfix_check_sp( win7: 2 ) > 0){
	if(version_in_range( version: sysVer, test_version: "6.1.7600.16000", test_version2: "6.1.7600.16832" ) || version_in_range( version: sysVer, test_version: "6.1.7600.20000", test_version2: "6.1.7600.20986" ) || version_in_range( version: sysVer, test_version: "6.1.7601.17000", test_version2: "6.1.7601.17631" ) || version_in_range( version: sysVer, test_version: "6.1.7601.21000", test_version2: "6.1.7601.21746" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

