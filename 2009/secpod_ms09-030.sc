if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900391" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-07-15 20:20:16 +0200 (Wed, 15 Jul 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-0566" );
	script_bugtraq_id( 35599 );
	script_name( "Microsoft Office Publisher Remote Code Execution Vulnerability (969516)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc", "secpod_ms_office_detection_900025.sc" );
	script_mandatory_keys( "MS/Office/Ver", "SMB/Office/Publisher/Version" );
	script_tag( name: "impact", value: "Successful exploitation could execute arbitrary code on the remote system
  via a specially crafted Publisher file." );
	script_tag( name: "affected", value: "- Microsoft Office 2007 SP1 and prior

  - Microsoft Office Publisher 2007 SP1 and prior" );
	script_tag( name: "insight", value: "The flaw is due to error in calculating object handler data when opening
  files created in older versions of Publisher. This can be exploited to
  corrupt memory and cause an invalid value to be dereferenced as a pointer." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS09-030." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/969693" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-030" );
	exit( 0 );
}
require("version_func.inc.sc");
officeVer = get_kb_item( "MS/Office/Ver" );
if(officeVer && IsMatchRegexp( officeVer, "^12\\." )){
	pubVer = get_kb_item( "SMB/Office/Publisher/Version" );
	if(!pubVer || !IsMatchRegexp( pubVer, "^12\\." )){
		exit( 0 );
	}
	if(version_in_range( version: pubVer, test_version: "12.0", test_version2: "12.0.6501.4999" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

