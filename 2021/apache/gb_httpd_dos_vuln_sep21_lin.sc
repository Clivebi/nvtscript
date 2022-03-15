CPE = "cpe:/a:apache:http_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146727" );
	script_version( "2021-09-29T08:01:30+0000" );
	script_tag( name: "last_modification", value: "2021-09-29 08:01:30 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-17 11:53:54 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-27 17:34:00 +0000 (Mon, 27 Sep 2021)" );
	script_cve_id( "CVE-2021-36160" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Apache HTTP Server 2.4.30 < 2.4.49 DoS Vulnerability - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_http_server_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "apache/http_server/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "Apache HTTP Server is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A carefully crafted request uri-path can cause mod_proxy_uwsgi
  to read above the allocated memory and crash (DoS)." );
	script_tag( name: "affected", value: "Apache HTTP Server version 2.4.30 through 2.4.48." );
	script_tag( name: "solution", value: "Update to version 2.4.49 or later." );
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
if(version_in_range( version: version, test_version: "2.4.30", test_version2: "2.4.48" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.4.49", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

