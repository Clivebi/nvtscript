if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113795" );
	script_version( "2021-08-26T06:01:00+0000" );
	script_tag( name: "last_modification", value: "2021-08-26 06:01:00 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-03-09 11:56:31 +0000 (Tue, 09 Mar 2021)" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-11 21:13:00 +0000 (Thu, 11 Mar 2021)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2009-20001" );
	script_name( "MantisBT < 2.24.5 Session Hijacking Vulnerability - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "mantis_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "mantisbt/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "MantisBT is prone to a session hijacking vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Session cookies don't expire upon logout, allowing an attacker
  who previously gained access to another user's cookie to impersonate that user." );
	script_tag( name: "affected", value: "MantisBT through version 2.24.4." );
	script_tag( name: "solution", value: "Update to version 2.24.5 or later." );
	script_xref( name: "URL", value: "https://mantisbt.org/bugs/view.php?id=27976" );
	exit( 0 );
}
CPE = "cpe:/a:mantisbt:mantisbt";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "2.24.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.24.5", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

