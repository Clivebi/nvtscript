CPE = "cpe:/a:rubyonrails:rails";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901184" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)" );
	script_cve_id( "CVE-2011-0447" );
	script_bugtraq_id( 46291 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Ruby on Rails Cross Site Request Forgery Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_rails_consolidation.sc" );
	script_mandatory_keys( "rails/detected" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2011/0343" );
	script_xref( name: "URL", value: "http://groups.google.com/group/rubyonrails-security/msg/365b8a23b76a6b4a?dmode=source&output=gplain" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to conduct cross site request
  forgery attacks by using combinations of browser plugins and HTTP redirections." );
	script_tag( name: "affected", value: "Ruby on Rails versions 2.1.x, 2.2.x, and 2.3.x before 2.3.11, and 3.x before 3.0.4." );
	script_tag( name: "insight", value: "The flaw is caused by input validation errors in the CSRF protection feature,
  which could allow attackers to conduct cross site request forgery attacks by using combinations of browser plugins
  and HTTP redirections." );
	script_tag( name: "solution", value: "Upgrade to Ruby on Rails version 3.0.4 or 2.3.11." );
	script_tag( name: "summary", value: "This host is running Ruby on Rails and is prone to cross site
  request forgery vulnerabilities." );
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
if(version_in_range( version: version, test_version: "2.1", test_version2: "2.3.10" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.3.11", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "3.0.0", test_version2: "3.0.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.0.4", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

