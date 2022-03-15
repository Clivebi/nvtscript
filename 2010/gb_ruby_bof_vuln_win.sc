CPE = "cpe:/a:ruby-lang:ruby";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801375" );
	script_version( "2020-07-14T14:24:25+0000" );
	script_tag( name: "last_modification", value: "2020-07-14 14:24:25 +0000 (Tue, 14 Jul 2020)" );
	script_tag( name: "creation_date", value: "2010-07-16 19:44:55 +0200 (Fri, 16 Jul 2010)" );
	script_cve_id( "CVE-2010-2489" );
	script_bugtraq_id( 41321 );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Ruby 'ARGF.inplace_mode' Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/40442" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/60135" );
	script_xref( name: "URL", value: "http://svn.ruby-lang.org/repos/ruby/tags/v1_9_1_429/ChangeLog" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_ruby_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "ruby/detected", "Host/runs_windows" );
	script_tag( name: "insight", value: "The flaw caused by improper bounds checking when handling filenames on Windows
  systems. It is not properly validating value assigned to the 'ARGF.inplace_mode' variable." );
	script_tag( name: "solution", value: "Upgrade to Ruby version 1.9.1-p429 or later." );
	script_tag( name: "summary", value: "This host is installed with Ruby and is prone to buffer overflow
  vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow local attackers to cause buffer overflow
  and execute arbitrary code on the system or cause the application to crash." );
	script_tag( name: "affected", value: "Ruby version 1.9.x before 1.9.1-p429 on Windows." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "1.9.0", test_version2: "1.9.1.428" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.9.1-p429", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

