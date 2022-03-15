CPE = "cpe:/a:apache:atlas";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112031" );
	script_version( "2021-09-13T08:01:46+0000" );
	script_cve_id( "CVE-2017-3150", "CVE-2017-3151", "CVE-2017-3152", "CVE-2017-3153", "CVE-2017-3154", "CVE-2017-3155" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-13 08:01:46 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-06 01:29:00 +0000 (Wed, 06 Sep 2017)" );
	script_tag( name: "creation_date", value: "2017-08-31 14:16:09 +0200 (Thu, 31 Aug 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Apache Atlas Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "This host is running Apache Atlas and is
  prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Apache Atlas versions 0.6.0-incubating and 0.7.0-incubating are vulnerable." );
	script_tag( name: "solution", value: "Update to version 0.7.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://lists.apache.org/thread.html/4a4fef91e067fd0d9da569e30867c1fa65e2a0520acde71ddefee0ea@%3Cdev.atlas.apache.org%3E" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_atlas_detect.sc" );
	script_mandatory_keys( "Apache/Atlas/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_equal( version: vers, test_version: "0.6.0" ) || version_is_equal( version: vers, test_version: "0.7.0" )){
	vuln = TRUE;
	fix = "0.7.1";
}
if(vuln){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

