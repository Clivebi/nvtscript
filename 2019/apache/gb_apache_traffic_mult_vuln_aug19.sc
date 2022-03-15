CPE = "cpe:/a:apache:traffic_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143069" );
	script_version( "2021-09-02T13:01:30+0000" );
	script_tag( name: "last_modification", value: "2021-09-02 13:01:30 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-10-28 05:08:21 +0000 (Mon, 28 Oct 2019)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-09 00:15:00 +0000 (Wed, 09 Dec 2020)" );
	script_cve_id( "CVE-2019-9512", "CVE-2019-9514", "CVE-2019-9515", "CVE-2019-10079" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Apache Traffic Server (ATS) Multiple HTTP/2 DoS vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_apache_traffic_detect.sc" );
	script_mandatory_keys( "apache_trafficserver/installed" );
	script_tag( name: "summary", value: "Apache Traffic Server is prone to multiple denial of service vulnerabilities
  in the HTTP/2 implementation." );
	script_tag( name: "insight", value: "Apache Traffic Server is prone to multiple denial of service vulnerabilities:

  - Ping Flood (CVE-2019-9512)

  - Reset Flood (CVE-2019-9514)

  - Settings Flood (CVE-2019-9515)

  - Malformed SETTINGS frames (CVE-2019-10079)" );
	script_tag( name: "affected", value: "Apache Traffic Server versions 6.0.0 - 6.2.3, 7.0.0 - 7.1.6 and 8.0.0 - 8.0.3." );
	script_tag( name: "solution", value: "Update to version 7.1.7, 8.0.4 or later." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_xref( name: "URL", value: "https://lists.apache.org/thread.html/bde52309316ae798186d783a5e29f4ad1527f61c9219a289d0eee0a7@%3Cdev.trafficserver.apache.org%3E" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "6.0.0", test_version2: "6.2.3" ) || version_in_range( version: version, test_version: "7.0.0", test_version2: "7.1.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.1.7" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "8.0.0", test_version2: "8.0.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.0.4" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

