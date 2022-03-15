if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902283" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-08-30 16:09:21 +0200 (Mon, 30 Aug 2010)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2010-3450", "CVE-2010-3451", "CVE-2010-3452", "CVE-2010-3453", "CVE-2010-3454", "CVE-2010-4253", "CVE-2010-4643" );
	script_bugtraq_id( 46031 );
	script_name( "OpenOffice.org Buffer Overflow and Directory Traversal Vulnerabilities (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/43065" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2011/0230" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2011/0232" );
	script_xref( name: "URL", value: "http://www.cs.brown.edu/people/drosenbe/research.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_openoffice_detect_win.sc" );
	script_mandatory_keys( "OpenOffice/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to execute arbitrary
  code in the context of the application. Failed exploit attempts will crash
  the application." );
	script_tag( name: "affected", value: "OpenOffice Version 2.x and 3.x to 3.2.0 on windows." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - A buffer overflow error when processing malformed TGA files and PNG files

  - A memory corruption error within the 'WW8ListManager::WW8ListManager()'
    and 'WW8DopTypography::ReadFromMem()' function when processing malformed
    data

  - A memory corruption error when processing malformed RTF data

  - A directory traversal error related to 'zip/jar' package extraction

  - A buffer overflow error when processing malformed PPT files" );
	script_tag( name: "solution", value: "Upgrade to OpenOffice Version 3.3.0 or later" );
	script_tag( name: "summary", value: "The host has OpenOffice installed and is prone to buffer overflow
  and directory traversal vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
openVer = get_kb_item( "OpenOffice/Win/Ver" );
if(!openVer){
	exit( 0 );
}
if(IsMatchRegexp( openVer, "^2.*" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}
if(IsMatchRegexp( openVer, "^3.*" )){
	if(version_is_less( version: openVer, test_version: "3.3.9567" )){
		report = report_fixed_ver( installed_version: openVer, fixed_version: "3.3.9567" );
		security_message( port: 0, data: report );
	}
}

