if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902956" );
	script_version( "2021-08-05T12:20:54+0000" );
	script_cve_id( "CVE-2013-0079" );
	script_bugtraq_id( 58369 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-05 12:20:54 +0000 (Thu, 05 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-03-13 13:32:19 +0530 (Wed, 13 Mar 2013)" );
	script_name( "Microsoft Visio Remote Code Execution Vulnerability (2801261)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2760762" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1028276" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-023" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary code." );
	script_tag( name: "affected", value: "Microsoft Visio 2010 Service Pack 1 and prior." );
	script_tag( name: "insight", value: "The flaw is caused by a type confusion error when handling Tree objects
  and can be exploited via a specially crafted Visio file." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS13-023." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
sysPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" + "\\App Paths\\visio.exe", item: "Path" );
if(!sysPath){
	exit( 0 );
}
exeVer = fetch_file_version( sysPath: sysPath, file_name: "visio.exe" );
if(exeVer && IsMatchRegexp( exeVer, "^14\\." )){
	if(version_in_range( version: exeVer, test_version: "14.0", test_version2: "14.0.6122.4999" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

