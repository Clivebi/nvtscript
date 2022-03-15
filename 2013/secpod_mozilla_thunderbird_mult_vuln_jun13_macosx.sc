if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.903220" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2013-1684", "CVE-2013-1685", "CVE-2013-1686", "CVE-2013-1687", "CVE-2013-1690", "CVE-2013-1692", "CVE-2013-1693", "CVE-2013-1694", "CVE-2013-1697", "CVE-2013-1682" );
	script_bugtraq_id( 60766, 60773, 60774, 60777, 60778, 60783, 60787, 60776, 60784, 60765 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2013-06-26 18:30:45 +0530 (Wed, 26 Jun 2013)" );
	script_name( "Mozilla Thunderbird Multiple Vulnerabilities - June 13 (Mac OS X)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/53970" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1028702" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2013/mfsa2013-50.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Thunderbird/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code,
  obtain potentially sensitive information, gain escalated privileges, bypass
  security restrictions, and perform unauthorized actions. Other attacks may
  also be possible." );
	script_tag( name: "affected", value: "Thunderbird version before 17.0.7 on Mac OS X" );
	script_tag( name: "insight", value: "Multiple flaws due to:

  - PreserveWrapper does not handle lack of wrapper.

  - Error in processing of SVG format images with filters to read pixel values.

  - Does not prevent inclusion of body data in XMLHttpRequest HEAD request.

  - Multiple unspecified vulnerabilities in the browser engine.

  - Does not properly handle onreadystatechange events in conjunction with
    page reloading.

  - System Only Wrapper (SOW) and Chrome Object Wrapper (COW), does not
    restrict XBL user-defined functions.

  - Use-after-free vulnerability in 'nsIDocument::GetRootElement' and
    'mozilla::dom::HTMLMediaElement::LookupMediaElementURITable' functions.

  - XrayWrapper does not properly restrict use of DefaultValue for method calls." );
	script_tag( name: "solution", value: "Upgrade to Thunderbird version to 17.0.7 or later." );
	script_tag( name: "summary", value: "This host is installed with Mozilla Thunderbird and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vers = get_kb_item( "Thunderbird/MacOSX/Version" );
if(vers){
	if(version_is_less( version: vers, test_version: "17.0.6" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "17.0.6" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}

