CPE = "cpe:/a:postgresql:postgresql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812956" );
	script_version( "2021-09-29T12:07:39+0000" );
	script_cve_id( "CVE-2018-1052" );
	script_bugtraq_id( 102987 );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-29 12:07:39 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:38:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-02-28 11:48:11 +0530 (Wed, 28 Feb 2018)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "PostgreSQL Information Disclosure Vulnerability-01 Feb18 - Windows" );
	script_tag( name: "summary", value: "PostgreSQL is prone to an information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error in the
  processing of partition keys containing multiple expressions." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  authenticated attacker to gain access to sensitive information that may aid
  in further attacks." );
	script_tag( name: "affected", value: "PostgreSQL version 10.x before
  10.2." );
	script_tag( name: "solution", value: "Update to version 10.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.postgresql.org/about/news/1829" );
	script_xref( name: "URL", value: "https://www.postgresql.org/docs/current/static/release-10-2.html" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Databases" );
	script_dependencies( "postgresql_detect.sc", "secpod_postgresql_detect_lin.sc", "secpod_postgresql_detect_win.sc", "os_detection.sc" );
	script_mandatory_keys( "postgresql/detected", "Host/runs_windows" );
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
loc = infos["location"];
if(IsMatchRegexp( vers, "^10\\." )){
	if(version_is_less( version: vers, test_version: "10.2" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "10.2", install_path: loc );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

