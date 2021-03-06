CPE = "cpe:/a:vbulletin:vbulletin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100020" );
	script_version( "2019-09-27T07:10:39+0000" );
	script_tag( name: "last_modification", value: "2019-09-27 07:10:39 +0000 (Fri, 27 Sep 2019)" );
	script_tag( name: "creation_date", value: "2009-03-10 08:40:52 +0100 (Tue, 10 Mar 2009)" );
	script_bugtraq_id( 32348 );
	script_cve_id( "CVE-2008-6256" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_name( "vBulletin 'admincalendar.php' SQL Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "vbulletin_detect.sc" );
	script_mandatory_keys( "vbulletin/detected" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to the newest version of vBulletin." );
	script_tag( name: "summary", value: "vBulletin is prone to an SQL-injection vulnerability because it
  fails to sufficiently sanitize user-supplied data before using it in
  an SQL query." );
	script_tag( name: "impact", value: "Exploiting this issue could allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities in the underlying database.

  Note that to succeed, the attacker must have an administrative
  account with 'calendar' administrator access." );
	script_tag( name: "affected", value: "vBulletin 3.7.3.pl1 is vulnerable, other versions may also be affected." );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less_equal( version: vers, test_version: "3.7.3.pl1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "Unknown", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

