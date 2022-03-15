if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902133" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-03-10 15:48:25 +0100 (Wed, 10 Mar 2010)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2010-0257", "CVE-2010-0258", "CVE-2010-0260", "CVE-2010-0261", "CVE-2010-0262", "CVE-2010-0263", "CVE-2010-0264" );
	script_bugtraq_id( 38547, 38550, 38551, 38552, 38553, 38554, 38555 );
	script_name( "Microsoft Office Excel Multiple Vulnerabilities (980150)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/978474" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/0566" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-017" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc", "secpod_ms_office_detection_900025.sc" );
	script_mandatory_keys( "MS/Office/Ver", "MS/Office/Prdts/Installed" );
	script_tag( name: "impact", value: "Successful exploitation could allow execution of arbitrary code on the
  remote system and corrupt memory, cause buffer overflow via a specially crafted Excel file." );
	script_tag( name: "affected", value: "- Microsoft Excel Viewer 2003/2007

  - Microsoft Office Excel 2002/2003/2007

  - Microsoft Office Compatibility Pack for, Excel, PowerPoint 2007 File Formats SP 1/2" );
	script_tag( name: "insight", value: "- Memory corruption error when processing malformed 'EntExU2', 'BRAI'
  'MDXTuple', 'ContinueFRT12', 'MDXSet', 'ContinueFRT12', 'FnGroupName',
  'BuiltInFnGroupCount', 'DbOrParamQry' and 'FnGrp12' records, which could
  be exploited by attackers to execute arbitrary code by tricking a user
  into opening a specially crafted Excel document.

  - An uninitialized pointer error when processing malformed data." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS10-017." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
if(hotfix_check_sp( win2k: 5, xp: 4, win2003: 3 ) <= 0){
	exit( 0 );
}
excelVer = get_kb_item( "SMB/Office/Excel/Version" );
if(excelVer && IsMatchRegexp( excelVer, "^1[012]\\." )){
	if(version_in_range( version: excelVer, test_version: "10.0", test_version2: "10.0.6859" ) || version_in_range( version: excelVer, test_version: "11.0", test_version2: "11.0.8319" ) || version_in_range( version: excelVer, test_version: "12.0", test_version2: "12.0.6524.5002" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
cmpPckVer = get_kb_item( "SMB/Office/ComptPack/Version" );
if(cmpPckVer && IsMatchRegexp( cmpPckVer, "^12\\." )){
	xlcnvVer = get_kb_item( "SMB/Office/XLCnv/Version" );
	if(xlcnvVer && IsMatchRegexp( xlcnvVer, "^12\\." )){
		if(version_in_range( version: xlcnvVer, test_version: "12.0", test_version2: "12.0.6529.4999" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
			exit( 0 );
		}
	}
}
xlviewVer = get_kb_item( "SMB/Office/XLView/Version" );
if(xlviewVer && IsMatchRegexp( xlviewVer, "^12\\." )){
	if(version_in_range( version: xlviewVer, test_version: "12.0", test_version2: "12.0.6524.5003" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

