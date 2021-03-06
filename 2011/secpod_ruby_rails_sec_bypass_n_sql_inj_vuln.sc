CPE = "cpe:/a:rubyonrails:rails";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901187" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-02-28 11:12:07 +0100 (Mon, 28 Feb 2011)" );
	script_cve_id( "CVE-2011-0448", "CVE-2011-0449" );
	script_bugtraq_id( 46292 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Ruby on Rails Security Bypass and SQL Injection Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_rails_consolidation.sc" );
	script_mandatory_keys( "rails/detected" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/43278" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1025063" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1025061" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2011/0343" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to bypass certain security
  restrictions and conduct SQL injection attacks." );
	script_tag( name: "affected", value: "Ruby on Rails versions 3.x before 3.0.4." );
	script_tag( name: "insight", value: "- The filtering code does not properly work for case insensitive file
  systems, which can be exploited to bypass the filter by varying the case
  in certain action parameters.

  - Input passed to the 'limit()' function is not properly sanitised before
  being used in SQL queries. This can be exploited to manipulate SQL queries
  by injecting arbitrary SQL code." );
	script_tag( name: "solution", value: "Upgrade to Ruby on Rails version 3.0.4 or later." );
	script_tag( name: "summary", value: "This host is running Ruby on Rails and is prone to security bypass
  and SQL injection vulnerabilities." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_in_range( version: version, test_version: "3.0.0", test_version2: "3.0.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.0.4", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

