if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902284" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-02-05 04:12:38 +0100 (Sat, 05 Feb 2011)" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2010-3689" );
	script_bugtraq_id( 46031 );
	script_name( "OpenOffice.org 'soffice' Directory Traversal Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/43065" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2011/0232" );
	script_xref( name: "URL", value: "http://www.cs.brown.edu/people/drosenbe/research.html" );
	script_xref( name: "URL", value: "http://www.openoffice.org/security/cves/CVE-2010-3689.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_openoffice_detect_win.sc" );
	script_mandatory_keys( "OpenOffice/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allows local users to gain privileges via
  a Trojan horse shared library in the current working directory." );
	script_tag( name: "affected", value: "OpenOffice Version 3.x to 3.2.0 on Windows" );
	script_tag( name: "insight", value: "The flaw is due to an error in 'soffice', which places a zero-length
  directory name in the 'LD_LIBRARY_PATH'." );
	script_tag( name: "solution", value: "Upgrade to OpenOffice Version 3.3.0 or later" );
	script_tag( name: "summary", value: "The host has OpenOffice installed and is prone to directory
  traversal vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
openVer = get_kb_item( "OpenOffice/Win/Ver" );
if(!openVer){
	exit( 0 );
}
if(IsMatchRegexp( openVer, "^3.*" )){
	if(version_is_less( version: openVer, test_version: "3.3.9567" )){
		report = report_fixed_ver( installed_version: openVer, fixed_version: "3.3.9567" );
		security_message( port: 0, data: report );
	}
}

