if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900570" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-06-23 10:30:45 +0200 (Tue, 23 Jun 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-1904" );
	script_bugtraq_id( 35278 );
	script_name( "Ruby BigDecimal Library Denial of Service Vulnerability (Linux)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/34135" );
	script_xref( name: "URL", value: "http://www.ruby-lang.org/en/news/2009/06/09/dos-vulnerability-in-bigdecimal/" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_ruby_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "ruby/detected", "Host/runs_unixoide" );
	script_tag( name: "impact", value: "Attackers can exploit this issue to crash an application using this library." );
	script_tag( name: "affected", value: "Ruby 1.8.6 to 1.8.6-p368 and 1.8.7 to 1.8.7-p172 on Linux." );
	script_tag( name: "insight", value: "The flaw is due to an error within the BigDecimal standard library
  when trying to convert BigDecimal objects into floating point numbers
  which leads to segmentation fault." );
	script_tag( name: "solution", value: "Upgrade to 1.8.6-p369 or 1.8.7-p174." );
	script_tag( name: "summary", value: "The host is installed with Ruby and is prone to denial of
  service  vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
CPE = "cpe:/a:ruby-lang:ruby";
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
if(version_in_range( version: version, test_version: "1.8.6", test_version2: "1.8.6.367" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.8.6-p369", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "1.8.7", test_version2: "1.8.7.172" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.8.7-p174", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

