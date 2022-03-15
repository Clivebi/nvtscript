CPE = "cpe:/a:nginx:nginx";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143351" );
	script_version( "2021-07-08T02:00:55+0000" );
	script_tag( name: "last_modification", value: "2021-07-08 02:00:55 +0000 (Thu, 08 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-01-14 03:57:07 +0000 (Tue, 14 Jan 2020)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-15 21:15:00 +0000 (Wed, 15 Jan 2020)" );
	script_cve_id( "CVE-2019-20372" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "nginx 0.7.12 < 1.17.7 HTTP Request Smuggling Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_nginx_consolidation.sc" );
	script_mandatory_keys( "nginx/detected" );
	script_tag( name: "summary", value: "nginx, with certain error_page configurations, allows HTTP request smuggling,
  as demonstrated by the ability of an attacker to read unauthorized web pages in environments where nginx is
  being fronted by a load balancer." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "nginx versions 0.7.12 - 1.17.6." );
	script_tag( name: "solution", value: "Update to version 1.17.7 or later." );
	script_xref( name: "URL", value: "https://nginx.org/en/CHANGES" );
	script_xref( name: "URL", value: "https://bertjwregeer.keybase.pub/2019-12-10%20-%20error_page%20request%20smuggling.pdf" );
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
if(version_in_range( version: version, test_version: "0.7.12", test_version2: "1.17.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.17.7", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

