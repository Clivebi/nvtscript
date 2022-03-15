CPE = "cpe:/a:egroupware:egroupware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108066" );
	script_version( "$Revision: 11863 $" );
	script_cve_id( "CVE-2014-2987", "CVE-2014-2988" );
	script_bugtraq_id( 67303, 67409 );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2017-02-01 09:00:00 +0100 (Wed, 01 Feb 2017)" );
	script_name( "EGroupware Multiple CSRF and Remote Code Execution Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (c) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_egroupware_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "egroupware/installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/67303" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/67409" );
	script_xref( name: "URL", value: "http://www.egroupware.org/" );
	script_tag( name: "summary", value: "EGroupware is prone to multiple CSRF and remote PHP code-execution vulnerabilities." );
	script_tag( name: "impact", value: "Successfully exploiting these issues will allow attackers to execute arbitrary
  code within the context of the application." );
	script_tag( name: "affected", value: "EGroupware Enterprise Line (EPL) before 11.1.20140505, EGroupware Community Edition
  before 1.8.007.20140506, and EGroupware before 14.1 beta." );
	script_tag( name: "solution", value: "Upgrade to:

  - EGroupware Enterprise Line (EPL) 11.1.20140505 or later

  - EGroupware Community Edition 1.8.007.20140506 or later

  - EGroupware 14.1 beta or later" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "1.8.007" )){
	vuln = TRUE;
	fix = "1.8.007.20140506";
}
if(version_in_range( version: vers, test_version: "9", test_version2: "11.1.20140416" )){
	vuln = TRUE;
	fix = "11.1.20140505";
}
if(vuln){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

