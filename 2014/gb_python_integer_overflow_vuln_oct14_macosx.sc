CPE = "cpe:/a:python:python";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804940" );
	script_version( "2021-02-15T14:13:17+0000" );
	script_cve_id( "CVE-2014-7185" );
	script_bugtraq_id( 70089 );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-02-15 14:13:17 +0000 (Mon, 15 Feb 2021)" );
	script_tag( name: "creation_date", value: "2014-10-17 14:35:32 +0530 (Fri, 17 Oct 2014)" );
	script_name( "Python Integer Overflow Vulnerability 01 Oct14 (Mac OS X)" );
	script_tag( name: "summary", value: "Python is prone to an integer overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as the user-supplied input is not properly
  validated when handling large buffer sizes and/or offsets." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to gain
  access to potentially sensitive information or cause a denial of service." );
	script_tag( name: "affected", value: "Python 2.7.x before version 2.7.8." );
	script_tag( name: "solution", value: "Update to version 2.7.8 or later." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://bugs.python.org/issue2183" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/96193" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_python_consolidation.sc" );
	script_mandatory_keys( "python/mac-os-x/detected" );
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
if(version_in_range( version: version, test_version: "2.7", test_version2: "2.7.7" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.7.8", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

