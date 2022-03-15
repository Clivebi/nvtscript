if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803656" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2012-5354", "CVE-2012-3989", "CVE-2012-3985", "CVE-2012-3984" );
	script_bugtraq_id( 55856 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-07-12 11:10:46 +0530 (Fri, 12 Jul 2013)" );
	script_name( "Mozilla Thunderbird Multiple Vulnerabilities - Oct 12 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/50856" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/50935" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-76.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-75.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-80.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_thunderbird_detect_portable_win.sc" );
	script_mandatory_keys( "Thunderbird/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to conduct cross-site scripting,
  clickjacking attacks or cause a denial of service or possibly execute
  arbitrary code." );
	script_tag( name: "affected", value: "Thunderbird versions before 16.0 on Windows" );
	script_tag( name: "insight", value: "The flaws are due to:

  - An error while handling navigation away from a web page that has multiple
    menus of SELECT elements active, which allows remote attackers to conduct
    clickjacking attacks.

  - An invalid cast when using the instance of operator on certain types of
    JavaScript objects.

  - An error when implementing the HTML5 Same Origin Policy, which allows
    remote attackers to conduct cross-site scripting (XSS) attacks by
    leveraging initial-origin access after document.domain has been set." );
	script_tag( name: "solution", value: "Upgrade to Thunderbird version 16.0 or later." );
	script_tag( name: "summary", value: "The host is installed with Mozilla Thunderbird and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vers = get_kb_item( "Thunderbird/Win/Ver" );
if(vers){
	if(version_is_less( version: vers, test_version: "16.0" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "16.0" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

