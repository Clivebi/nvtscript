CPE = "cpe:/a:postgresql:postgresql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142686" );
	script_version( "2021-08-31T13:01:28+0000" );
	script_tag( name: "last_modification", value: "2021-08-31 13:01:28 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-08-01 07:05:27 +0000 (Thu, 01 Aug 2019)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-04 18:15:00 +0000 (Fri, 04 Dec 2020)" );
	script_cve_id( "CVE-2019-10129" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "PostgreSQL 11.x < 11.3 Memory Disclosure Vulnerability (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "postgresql_detect.sc", "secpod_postgresql_detect_lin.sc", "secpod_postgresql_detect_win.sc", "os_detection.sc" );
	script_mandatory_keys( "postgresql/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "PostgreSQL is prone to a memory disclosure vulnerability in the partition
  routing." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "An attacker can read arbitrary bytes of server memory by executing a
  purpose-crafted INSERT statement to a partitioned table." );
	script_tag( name: "affected", value: "PostgreSQL version 11.x prior to 11.3." );
	script_tag( name: "solution", value: "Update to version 11.3 or later." );
	script_xref( name: "URL", value: "https://www.postgresql.org/about/news/1939/" );
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
if(version_in_range( version: version, test_version: "11.0", test_version2: "11.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "11.3", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

