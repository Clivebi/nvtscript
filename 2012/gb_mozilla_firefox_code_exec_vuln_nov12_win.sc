if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803061" );
	script_version( "2020-04-22T10:27:30+0000" );
	script_cve_id( "CVE-2012-4206", "CVE-2012-4210" );
	script_bugtraq_id( 56625, 56646 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-22 10:27:30 +0000 (Wed, 22 Apr 2020)" );
	script_tag( name: "creation_date", value: "2012-11-26 14:52:10 +0530 (Mon, 26 Nov 2012)" );
	script_name( "Mozilla Firefox Code Execution Vulnerabilities - November12 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/51358" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1027791" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1027792" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-98.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-104.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to gain privileges or execute
  arbitrary code in the context of the browser." );
	script_tag( name: "affected", value: "Mozilla Firefox version before 17.0 on Windows" );
	script_tag( name: "insight", value: "- Improper loading of DLL file in the default downloads directory by Firefox
    installer.

  - An error within Style Inspector when parsing style sheets can be exploited
    to execute HTML and CSS code in chrome privileged context." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 17.0 later." );
	script_tag( name: "summary", value: "This host is installed with Mozilla Firefox and is prone to multiple
  code execution vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ffVer = get_kb_item( "Firefox/Win/Ver" );
if(ffVer){
	if(version_is_less( version: ffVer, test_version: "17.0" )){
		report = report_fixed_ver( installed_version: ffVer, fixed_version: "17.0" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}

