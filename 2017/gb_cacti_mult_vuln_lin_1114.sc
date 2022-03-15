if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113050" );
	script_version( "2021-09-08T14:01:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 14:01:33 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-14 12:30:30 +0100 (Tue, 14 Nov 2017)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2017-16785", "CVE-2017-16660", "CVE-2017-16661" );
	script_name( "Cacti 1.1.27 multiple vulnerabilities (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "cacti_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "cacti/installed", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "Cacti through 1.1.27 is prone to following vulnerabilities:

  - Reflected XSS

  - Authenticated information disclosure

  - Authenticated remote code execution" );
	script_tag( name: "vuldetect", value: "The script checks if the vulnerable version is present on the host." );
	script_tag( name: "impact", value: "Successful exploitation would allow an authenticated administrator to run arbitrary code on the host." );
	script_tag( name: "affected", value: "Cacti through version 1.1.27" );
	script_tag( name: "solution", value: "Update Cacti to 1.1.28" );
	script_xref( name: "URL", value: "https://github.com/Cacti/cacti/issues/1066" );
	exit( 0 );
}
CPE = "cpe:/a:cacti:cacti";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "1.1.28" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.1.28" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

