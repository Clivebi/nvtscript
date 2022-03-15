CPE = "cpe:/a:apache:http_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141966" );
	script_version( "2021-09-02T13:01:30+0000" );
	script_tag( name: "last_modification", value: "2021-09-02 13:01:30 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-02-05 13:43:36 +0700 (Tue, 05 Feb 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-06 16:39:00 +0000 (Tue, 06 Jul 2021)" );
	script_cve_id( "CVE-2018-17189" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Apache HTTP Server < 2.4.38 HTTP/2 DoS Vulnerability (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_http_server_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "apache/http_server/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "By sending request bodies in a slow loris way to plain resources, the h2
  stream for that request unnecessarily occupied a server thread cleaning up that incoming data. This affects only
  HTTP/2 connections. A possible mitigation is to not enable the h2 protocol." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Apache HTTP Server version 2.4.37 and prior." );
	script_tag( name: "solution", value: "Update to version 2.4.38 or later." );
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
affected = make_list( "2.4.37",
	 "2.4.35",
	 "2.4.34",
	 "2.4.33",
	 "2.4.30",
	 "2.4.29",
	 "2.4.28",
	 "2.4.27",
	 "2.4.26",
	 "2.4.25",
	 "2.4.23",
	 "2.4.20",
	 "2.4.18",
	 "2.4.17" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "2.4.38", install_path: location );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

