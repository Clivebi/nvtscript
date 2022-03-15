CPE = "cpe:/a:mantisbt:mantisbt";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100804" );
	script_version( "2019-07-05T10:41:31+0000" );
	script_tag( name: "last_modification", value: "2019-07-05 10:41:31 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2010-09-15 16:23:15 +0200 (Wed, 15 Sep 2010)" );
	script_bugtraq_id( 43224 );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Mantis Multiple HTML Injection Vulnerabilities" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/43224" );
	script_xref( name: "URL", value: "http://www.mantisbt.org/bugs/changelog_page.php?version_id=111" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "mantis_detect.sc" );
	script_mandatory_keys( "mantisbt/detected" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "solution", value: "The vendor released an update. Please see the references for more
  information." );
	script_tag( name: "summary", value: "Mantis is prone to multiple HTML-injection vulnerabilities because the
  application fails to properly sanitize user-supplied input before using it in dynamically generated content." );
	script_tag( name: "impact", value: "Attacker-supplied HTML and script code would run in the context of the
  affected browser, potentially allowing the attacker to steal cookie-based authentication credentials or
  to control how the site is rendered to the user. Other attacks are also possible." );
	script_tag( name: "affected", value: "Versions prior to Mantis 1.2.3 vulnerable." );
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
path = infos["location"];
if(version_is_less( version: version, test_version: "1.2.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.2.3", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

