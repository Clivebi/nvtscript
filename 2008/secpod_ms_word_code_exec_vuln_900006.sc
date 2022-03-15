if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900006" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-08-19 14:38:55 +0200 (Tue, 19 Aug 2008)" );
	script_bugtraq_id( 30124 );
	script_cve_id( "CVE-2008-2244" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_category( ACT_GATHER_INFO );
	script_family( "Windows" );
	script_name( "Microsoft Word Could Allow Remote Code Execution Vulnerability" );
	script_dependencies( "smb_reg_service_pack.sc", "secpod_office_products_version_900032.sc", "secpod_ms_office_detection_900025.sc" );
	script_mandatory_keys( "MS/Office/Ver", "SMB/Office/Word/Version" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/43663" );
	script_xref( name: "URL", value: "http://www.frsirt.com/english/advisories/2008/2028" );
	script_xref( name: "URL", value: "http://www.microsoft.com/technet/security/advisory/953635" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-042" );
	script_tag( name: "summary", value: "This host is installed with Microsoft Office (with MS Word), which
  is prone to remote code execution vulnerability." );
	script_tag( name: "insight", value: "Flaw is due to an error within the handling of malformed/crafted MS Word documents." );
	script_tag( name: "affected", value: "- Microsoft Word 2002 (XP) with SP3

  - Microsoft Word 2003 with SP3" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "impact", value: "Remote attacker could exploit by persuading victim to open a crafted
  documents to corrupt memory and cause the application to crash, and also allow
  to execute arbitrary code with the system privileges of the victim." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
officeVer = get_kb_item( "MS/Office/Ver" );
if(officeVer && IsMatchRegexp( officeVer, "^1[01]\\." )){
	wordVer = get_kb_item( "SMB/Office/Word/Version" );
	if(!wordVer || !IsMatchRegexp( wordVer, "^1[01]\\." )){
		exit( 0 );
	}
	if( version_in_range( version: wordVer, test_version: "10.0", test_version2: "10.0.6845" ) ){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	else {
		if(version_in_range( version: wordVer, test_version: "11.0", test_version2: "11.0.8226" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
	}
}

