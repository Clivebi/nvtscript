CPE = "cpe:/a:open-emr:openemr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142236" );
	script_version( "2021-09-06T14:01:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-06 14:01:33 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-04-09 14:19:47 +0000 (Tue, 09 Apr 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-23 18:15:00 +0000 (Thu, 23 Jan 2020)" );
	script_cve_id( "CVE-2018-18035" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OpenEMR < 5.0.1 Patch 6 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_openemr_detect.sc" );
	script_mandatory_keys( "openemr/installed" );
	script_tag( name: "summary", value: "A vulnerability in flashcanvas.swf in OpenEMR could allow an unauthenticated,
  remote attacker to conduct a cross-site scripting (XSS) attack on a targeted system." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "OpenEMR prior to version 5.0.1 Patch 6." );
	script_tag( name: "solution", value: "Update to version 5.0.1 Patch 6 or later." );
	script_xref( name: "URL", value: "https://www.open-emr.org/wiki/index.php/OpenEMR_Patches" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
path = infos["location"];
if(version_is_less( version: version, test_version: "5.0.1-6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.0.1-6", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

