CPE = "cpe:/a:zimbra:zimbra_collaboration_suite";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108067" );
	script_version( "$Revision: 11977 $" );
	script_cve_id( "CVE-2016-3999", "CVE-2016-3401", "CVE-2016-3402", "CVE-2016-3404", "CVE-2016-3407", "CVE-2016-3408", "CVE-2016-3409", "CVE-2016-3410", "CVE-2016-3411", "CVE-2016-3412", "CVE-2016-3413", "CVE-2016-3415", "CVE-2016-5721", "CVE-2015-4852" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-19 09:28:56 +0200 (Fri, 19 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2017-02-01 15:00:00 +0100 (Wed, 01 Feb 2017)" );
	script_name( "Zimbra Collaboration < 8.7.0 Multiple Vulnerabilities " );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (c) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_zimbra_admin_console_detect.sc" );
	script_require_ports( "Services/www", 80, 443, 7071, 7072 );
	script_mandatory_keys( "zimbra_web/installed" );
	script_xref( name: "URL", value: "https://wiki.zimbra.com/wiki/Zimbra_Releases/8.7.0#Security_Fixes" );
	script_xref( name: "URL", value: "https://wiki.zimbra.com/wiki/Zimbra_Security_Advisories" );
	script_tag( name: "summary", value: "Zimbra Collaboration is prone to multiple security vulnerabilities
  because it fails to sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary script code in the browser
  of an unsuspecting user in the context of the affected site. This may allow the attacker to steal cookie-based
  authentication credentials and launch other attacks.

  Other attacks are also possible due to further, unspecific vulnerabilities." );
	script_tag( name: "affected", value: "Zimbra Collaboration versions before 8.7.0 GA are vulnerable." );
	script_tag( name: "solution", value: "Upgrade Zimbra Collaboration to version 8.7.0 GA or later" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "8.7.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "8.7.0" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

