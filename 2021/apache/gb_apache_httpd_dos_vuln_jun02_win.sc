if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107964" );
	script_version( "2021-03-01T08:21:56+0000" );
	script_tag( name: "last_modification", value: "2021-03-01 08:21:56 +0000 (Mon, 01 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-02-02 12:07:31 +0100 (Tue, 02 Feb 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2002-0392" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Apache HTTP Server 1.2.2 - 1.3.24 / 2.0 - 2.0.36 DoS Vulnerability (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_http_server_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "apache/http_server/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "Apache HTTP Server is prone to a denial-of-service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "There is a remotely exploitable vulnerability in the way that Apache
  web servers (or other web servers based on their source code) handle data encoded in chunks. This
  vulnerability is present by default in configurations of Apache web server. The impact of this
  vulnerability is dependent upon the software version and the hardware platform the server is running on." );
	script_tag( name: "impact", value: "For Apache versions 1.2.2 through 1.3.24 inclusive, this vulnerability
  may allow the execution of arbitrary code by remote attackers. Exploits are publicly available that claim
  to allow the execution of arbitrary code.

  For Apache versions 2.0 through 2.0.36 inclusive, the condition causing the vulnerability is correctly
  detected and causes the child process to exit. Depending on a variety of factors, including the threading
  model supported by the vulnerable system, this may lead to a denial-of-service attack against the Apache
  web server." );
	script_tag( name: "affected", value: "Apache HTTP Server version 1.2.2 and above, 1.3 through 1.3.24, and versions
  2.0 through 2.0.36." );
	script_tag( name: "solution", value: "Update to version 1.3.26, 2.0.39 or later." );
	script_xref( name: "URL", value: "https://www.kb.cert.org/vuls/id/944335" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
CPE = "cpe:/a:apache:http_server";
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "^[0-9]+\\.[0-9]+\\.[0-9]+" )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_in_range( version: version, test_version: "1.2.2", test_version2: "1.3.24" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.3.26", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "2.0", test_version2: "2.0.36" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.0.39", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

