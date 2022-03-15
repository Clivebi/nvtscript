if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807362" );
	script_version( "2019-12-20T10:24:46+0000" );
	script_cve_id( "CVE-2016-3359" );
	script_bugtraq_id( 92795 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-12-20 10:24:46 +0000 (Fri, 20 Dec 2019)" );
	script_tag( name: "creation_date", value: "2016-09-14 12:23:33 +0530 (Wed, 14 Sep 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Outlook Remote Code Execution Vulnerability (3185852)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Bulletin MS16-107." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as office software fails to
  properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow a to execute
  arbitrary code in the context of the current user and to take control of the
  affected system." );
	script_tag( name: "affected", value: "- Microsoft Outlook 2007 Service Pack 2 and prior

  - Microsoft Outlook 2010 Service Pack 1 and prior

  - Microsoft Outlook 2016" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3118293" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3118303" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3118313" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-107" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/Office/Outlook/Version" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
outlookVer = get_kb_item( "SMB/Office/Outlook/Version" );
if(!outlookVer || !IsMatchRegexp( outlookVer, "^1[246]\\." )){
	exit( 0 );
}
outlookFile = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" + "\\App Paths\\OUTLOOK.EXE", item: "Path" );
if(outlookFile){
	outlookVer = fetch_file_version( sysPath: outlookFile, file_name: "outlook.exe" );
	if(outlookVer){
		if( version_in_range( version: outlookVer, test_version: "14.0", test_version2: "14.0.7172.4999" ) ){
			Vulnerable_range = "14.0 - 14.0.7172.4999";
			VULN = TRUE;
		}
		else {
			if( version_in_range( version: outlookVer, test_version: "12.0", test_version2: "12.0.6753.4999" ) ){
				Vulnerable_range = "12.0 - 12.0.6753.4999";
				VULN = TRUE;
			}
			else {
				if(version_in_range( version: outlookVer, test_version: "16.0", test_version2: "16.0.4432.1000" )){
					Vulnerable_range = "16.0 - 16.0.4432.1000";
					VULN = TRUE;
				}
			}
		}
	}
}
if(VULN){
	report = "File checked:     " + outlookFile + "outlook.exe" + "\n" + "File version:     " + outlookVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}
