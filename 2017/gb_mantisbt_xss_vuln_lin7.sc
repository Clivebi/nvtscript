CPE = "cpe:/a:mantisbt:mantisbt";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140267" );
	script_version( "2021-09-15T11:15:39+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 11:15:39 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-02 12:48:43 +0700 (Wed, 02 Aug 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-15 17:06:00 +0000 (Tue, 15 Aug 2017)" );
	script_cve_id( "CVE-2017-12061", "CVE-2017-12062" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "MantisBT Multiple XSS Vulnerabilities (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "mantis_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "mantisbt/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "MantisBT is prone to multiple cross-site scripting vulnerabilities." );
	script_tag( name: "insight", value: "MantisBT is prone to multiple cross-site scripting vulnerabilities:

  - XSS in /admin/install.php script (CVE-2017-12061)

  - XSS in manage_user_page.php (CVE-2017-12062)" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to version 1.3.12, 2.5.2 or later." );
	script_xref( name: "URL", value: "https://mantisbt.org/bugs/view.php?id=23146" );
	script_xref( name: "URL", value: "https://mantisbt.org/bugs/view.php?id=23166" );
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
if(version_is_less( version: version, test_version: "1.3.12" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.3.12" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "2.0", test_version2: "2.5.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.5.2" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

