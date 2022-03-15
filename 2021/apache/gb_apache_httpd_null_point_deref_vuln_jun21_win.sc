if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112900" );
	script_version( "2021-08-24T09:01:06+0000" );
	script_tag( name: "last_modification", value: "2021-08-24 09:01:06 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-06-10 09:23:11 +0000 (Thu, 10 Jun 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-17 08:15:00 +0000 (Sat, 17 Jul 2021)" );
	script_cve_id( "CVE-2020-13950" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Apache HTTP Server 2.4.41 - 2.4.46 NULL Pointer Dereference Vulnerability - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_http_server_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "apache/http_server/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "Apache HTTP Server is prone to a null pointer dereference
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "mod_proxy_http can be made to crash (NULL pointer dereference)
  with specially crafted requests using both Content-Length and Transfer-Encoding headers, leading
  to a Denial of Service." );
	script_tag( name: "affected", value: "Apache HTTP Server versions 2.4.41 to 2.4.46 on Windows." );
	script_tag( name: "solution", value: "Update to version 2.4.48 or later." );
	script_xref( name: "URL", value: "https://httpd.apache.org/security/vulnerabilities_24.html" );
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
if(version_in_range( version: version, test_version: "2.4.41", test_version2: "2.4.46" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.4.48", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

