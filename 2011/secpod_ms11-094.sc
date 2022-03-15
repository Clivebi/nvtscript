if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902492" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_cve_id( "CVE-2011-3396", "CVE-2011-3413" );
	script_bugtraq_id( 50967, 50964 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-12-14 08:36:00 +0530 (Wed, 14 Dec 2011)" );
	script_name( "Microsoft Office PowerPoint Remote Code Execution Vulnerabilities (2639142)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2596764" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2596843" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2596912" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-094" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-094" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "MS/Office/Ver", "SMB/Office/PowerPnt/Version" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary code by
  tricking a user into opening a malicious PPT file." );
	script_tag( name: "affected", value: "- Microsoft PowerPoint 2010

  - Microsoft PowerPoint 2007 Service Pack 2

  - Microsoft PowerPoint Viewer 2007 Service Pack 2

  - Microsoft Office Compatibility Pack for PowerPoint 2007 File Formats SP2" );
	script_tag( name: "insight", value: "The flaws are due to the application loading unspecified libraries in
  an insecure manner. This can be exploited to load an arbitrary library by
  tricking a user into opening a PowerPoint file located on a remote WebDAV or SMB share." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS11-094." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
officeVer = get_kb_item( "MS/Office/Ver" );
if(!officeVer || !IsMatchRegexp( officeVer, "^1[24]\\." )){
	exit( 0 );
}
pptVer = get_kb_item( "SMB/Office/PowerPnt/Version" );
if(pptVer && IsMatchRegexp( pptVer, "^1[24]\\." )){
	if(version_in_range( version: pptVer, test_version: "12.0", test_version2: "12.0.6600.999" ) || version_in_range( version: pptVer, test_version: "14.0", test_version2: "14.0.6009.999" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
ppviewVer = get_kb_item( "SMB/Office/PPView/Version" );
if(ppviewVer && IsMatchRegexp( ppviewVer, "^12\\." )){
	if(version_in_range( version: ppviewVer, test_version: "12.0", test_version2: "12.0.6654.4999" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
if(registry_key_exists( key: "SOFTWARE\\Microsoft\\Office" )){
	sysPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "ProgramFilesDir" );
	if(sysPath){
		dllVer = fetch_file_version( sysPath: sysPath, file_name: "Microsoft Office\\Office12\\Ppcnv.dll" );
		if(dllVer && IsMatchRegexp( dllVer, "^12\\." )){
			if(version_in_range( version: dllVer, test_version: "12.0", test_version2: "12.0.6654.4999" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
		}
	}
}

