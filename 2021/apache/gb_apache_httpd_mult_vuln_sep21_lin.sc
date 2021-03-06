CPE = "cpe:/a:apache:http_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146836" );
	script_version( "2021-10-05T12:23:04+0000" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "creation_date", value: "2021-10-05 12:16:39 +0000 (Tue, 05 Oct 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2021-41524", "CVE-2021-41773" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Apache HTTP Server 2.4.49 Multiple Vulnerabilities - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_http_server_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "apache/http_server/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "Apache HTTP Server is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2021-41524: Null pointer dereference in h2 fuzzing

  - CVE-2021-41773: Path traversal and file disclosure" );
	script_tag( name: "affected", value: "Apache HTTP Server version 2.4.49." );
	script_tag( name: "solution", value: "Update to version 2.4.50 or later." );
	script_xref( name: "URL", value: "https://httpd.apache.org/security/vulnerabilities_24.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "^[0-9]+\\.[0-9]+\\.[0-9]+" )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_equal( version: version, test_version: "2.4.49" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.4.50", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

