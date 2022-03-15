CPE = "cpe:/a:otrs:otrs";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103933" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_bugtraq_id( 66569 );
	script_cve_id( "CVE-2014-2553", "CVE-2014-2554" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2014-04-03 12:44:23 +0200 (Thu, 03 Apr 2014)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "OTRS Help Desk Cross Site Scripting/Clickjacking Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "secpod_otrs_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "OTRS/installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/66569" );
	script_xref( name: "URL", value: "https://www.otrs.com/security-advisory-2014-04-xss-issue" );
	script_xref( name: "URL", value: "https://www.otrs.com/security-advisory-2014-05-clickjacking-issue/" );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected
  site. This may allow the attacker to steal cookie-based authentication
  credentials and launch other attacks." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Two vulnerabilities have been reported in OTRS Help
  Desk, which can be exploited by malicious people to conduct cross-site
  scripting and clickjacking attacks.

  1) Certain input related to dynamic fields is not properly sanitised
  before being returned to the user. This can be exploited to execute
  arbitrary HTML and script code in a user's browser session in context
  of an affected site.

  2) The application allows users to perform certain actions via HTTP
  requests via iframes without performing any validity checks to verify
  the requests. This can be exploited to perform certain unspecified
  actions by tricking a user into e.g. clicking a specially crafted link
  via clickjacking." );
	script_tag( name: "solution", value: "Upgrade to Open Ticket Request System (OTRS) 3.1.21, 3.2.16 or 3.3.6" );
	script_tag( name: "summary", value: "OTRS Help Desk is prone to a cross site scripting and to a clickjacking
  vulnerability because it fails to properly sanitize user-supplied input before using
  it in dynamically generated content." );
	script_tag( name: "affected", value: "Versions OTRS Help Desk prior to 3.1.21, 3.2.16 and 3.3.6 are
  vulnerable." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "3.2.0", test_version2: "3.2.15" ) || version_in_range( version: vers, test_version: "3.1.0", test_version2: "3.1.20" ) || version_in_range( version: vers, test_version: "3.3.0", test_version2: "3.3.5" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.1.21/3.2.16/3.3.6" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

