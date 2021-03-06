CPE = "cpe:/a:python:python";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900105" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_bugtraq_id( 30491 );
	script_cve_id( "CVE-2008-2315", "CVE-2008-2316", "CVE-2008-3142", "CVE-2008-3143", "CVE-2008-3144" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Buffer overflow" );
	script_name( "Python <= 2.5.2 Multiple Vulnerabilities (Windows)" );
	script_dependencies( "gb_python_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "python/detected", "Host/runs_windows" );
	script_xref( name: "URL", value: "http://bugs.python.org/issue2588" );
	script_xref( name: "URL", value: "http://bugs.python.org/issue2589" );
	script_xref( name: "URL", value: "http://bugs.python.org/issue2620" );
	script_tag( name: "summary", value: "Python is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "The flaws exist due to multiple integer overflows in:

  - hashlib module, which can lead to an unreliable cryptographic digest
  results.

  - the processing of unicode strings.

  - the PyOS_vsnprintf() function on architectures that do not have a
  vsnprintf() function.

  - the PyOS_vsnprintf() function when passing zero-length strings can
  lead to memory corruption." );
	script_tag( name: "affected", value: "Python 2.5.2 and prior." );
	script_tag( name: "solution", value: "A fix is available, please see the references for more
  information." );
	script_tag( name: "impact", value: "Successful exploitation would allow attackers to execute
  arbitrary code or create a denial of service condition." );
	script_tag( name: "qod_type", value: "remote_banner" );
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
vers = infos["version"];
path = infos["location"];
if(version_is_less_equal( version: vers, test_version: "2.5.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See references", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

