CPE = "cpe:/a:phppgadmin:phppgadmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103295" );
	script_version( "2020-02-19T07:25:11+0000" );
	script_tag( name: "last_modification", value: "2020-02-19 07:25:11 +0000 (Wed, 19 Feb 2020)" );
	script_tag( name: "creation_date", value: "2011-10-12 15:33:11 +0200 (Wed, 12 Oct 2011)" );
	script_bugtraq_id( 49914 );
	script_cve_id( "CVE-2011-3598" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "phpPgAdmin Multiple Cross-Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/49914" );
	script_xref( name: "URL", value: "http://freshmeat.net/projects/phppgadmin/releases/336969" );
	script_xref( name: "URL", value: "http://www.securelist.com/en/advisories/46248" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_phppgadmin_detect.sc" );
	script_mandatory_keys( "phppgadmin/detected" );
	script_tag( name: "solution", value: "Vendor updates are available. Please see the references for more
  information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "phpPgAdmin is prone to multiple cross-site scripting vulnerabilities
  because it fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker may leverage these issues to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected
  site. This may allow the attacker to steal cookie-based authentication
  credentials and launch other attacks." );
	script_tag( name: "affected", value: "phpPgAdmin 5.0.2 is vulnerable. Prior versions may also be affected." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less_equal( version: version, test_version: "5.0.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

