CPE = "cpe:/a:ruby-lang:ruby";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902559" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-08-29 16:22:41 +0200 (Mon, 29 Aug 2011)" );
	script_cve_id( "CVE-2011-3009" );
	script_bugtraq_id( 49126 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Ruby Random Number Values Information Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://redmine.ruby-lang.org/issues/show/4338" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2011/07/20/1" );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_ruby_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "ruby/detected", "Host/runs_windows" );
	script_tag( name: "impact", value: "Successful exploits may allow attackers to predict random number values." );
	script_tag( name: "affected", value: "Ruby Versions prior to Ruby 1.8.6-p114." );
	script_tag( name: "insight", value: "The flaw exists because ruby does not reset the random seed upon forking,
  which makes it easier for context-dependent attackers to predict the values
  of random numbers by leveraging knowledge of the number sequence obtained in
  a different child process." );
	script_tag( name: "solution", value: "Upgrade to Ruby version 1.8.6-p114 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is installed with Ruby and is prone to information
  disclosure vulnerability." );
	script_xref( name: "URL", value: "http://rubyforge.org/frs/?group_id=167" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "1.8.6.114" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.8.6.p114", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

