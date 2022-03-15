CPE = "cpe:/a:python:python";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804322" );
	script_version( "2021-02-15T14:13:17+0000" );
	script_cve_id( "CVE-2014-1912" );
	script_bugtraq_id( 65379 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-02-15 14:13:17 +0000 (Mon, 15 Feb 2021)" );
	script_tag( name: "creation_date", value: "2014-03-05 12:18:28 +0530 (Wed, 05 Mar 2014)" );
	script_name( "Python 'socket.recvfrom_into' Buffer Overflow Vulnerability Mar14 (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_python_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "python/detected", "Host/runs_windows" );
	script_xref( name: "URL", value: "http://bugs.python.org/issue20246" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/56624" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/31875" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1029831" );
	script_tag( name: "summary", value: "Python is prone to a buffer overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to a boundary error within the
  'sock_recvfrom_into' function." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote attacker to
  cause a buffer overflow, resulting in a denial of service or potentially allowing the
  execution of arbitrary code." );
	script_tag( name: "affected", value: "Python version 2.5 before 2.7.7 and 3.x before 3.3.4." );
	script_tag( name: "solution", value: "Update to Python version 2.7.7, 3.3.4 or later." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
if(version_in_range( version: version, test_version: "2.5", test_version2: "2.7.6" ) || version_in_range( version: location, test_version: "3.0", test_version2: "3.3.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.7.7/3.3.4", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

