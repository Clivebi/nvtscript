if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900081" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-12-26 14:23:17 +0100 (Fri, 26 Dec 2008)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-5679", "CVE-2008-5680", "CVE-2008-5681", "CVE-2008-5682", "CVE-2008-5683" );
	script_bugtraq_id( 32864 );
	script_name( "Opera Web Browser Multiple Vulnerabilities - Dec08 (Windows)" );
	script_xref( name: "URL", value: "http://www.opera.com/support/kb/view/920/" );
	script_xref( name: "URL", value: "http://www.opera.com/support/kb/view/921/" );
	script_xref( name: "URL", value: "http://www.opera.com/support/kb/view/923/" );
	script_xref( name: "URL", value: "http://www.opera.com/support/kb/view/924/" );
	script_xref( name: "URL", value: "http://www.opera.com/docs/changelogs/windows/963/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_opera_detect_portable_win.sc" );
	script_mandatory_keys( "Opera/Win/Version" );
	script_tag( name: "impact", value: "Successful remote attack could inject arbitrary code, information disclosure,
  execute java or plugin content and can even crash the application." );
	script_tag( name: "affected", value: "Opera version prior to 9.63 on Windows." );
	script_tag( name: "insight", value: "The flaws are due to

  - a buffer overflow error when handling certain text-area contents.

  - a memory corruption error when processing certain HTML constructs.

  - an input validation error in the feed preview feature when processing URLs.

  - an error in the built-in XSLT templates that incorrectly handle escaped
    content.

  - an error which could be exploited to reveal random data.

  - an error when processing SVG images embedded using img tags." );
	script_tag( name: "solution", value: "Upgrade to Opera 9.63." );
	script_tag( name: "summary", value: "The host is installed with Opera web browser and is prone to
  multiple Vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
operaVer = get_kb_item( "Opera/Win/Version" );
if(!operaVer){
	exit( 0 );
}
if(version_is_less( version: operaVer, test_version: "9.63" )){
	report = report_fixed_ver( installed_version: operaVer, fixed_version: "9.63" );
	security_message( port: 0, data: report );
}

