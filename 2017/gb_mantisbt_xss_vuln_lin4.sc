CPE = "cpe:/a:mantisbt:mantisbt";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108116" );
	script_version( "2021-09-08T13:01:42+0000" );
	script_cve_id( "CVE-2017-6973" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-08 13:01:42 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-12 01:29:00 +0000 (Wed, 12 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-04-05 09:33:23 +0200 (Wed, 05 Apr 2017)" );
	script_name( "MantisBT adm_config_report.php 'action' parameter Cross Site Scripting Vulnerability (Linux)" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "mantis_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "mantisbt/detected", "Host/runs_unixoide" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "http://www.mantisbt.org/bugs/view.php?id=22537" );
	script_tag( name: "summary", value: "This host is installed with MantisBT
  and is prone to a cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Successfully exploitation will allow remote
  attacker to execute arbitrary script code in the browser of an unsuspecting user
  in the context of the affected site. This may allow the attacker to steal
  cookie-based authentication credentials and to launch other attacks." );
	script_tag( name: "affected", value: "MantisBT versions before 1.3.8, 2.0.x/2.1.x before 2.1.2 and 2.2.x before 2.2.2" );
	script_tag( name: "solution", value: "Update to MantisBT 1.3.8, 2.1.2, or 2.2.2." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "1.3.8" )){
	vuln = TRUE;
	fix = "1.3.8";
}
if(IsMatchRegexp( vers, "^2\\.[01]" )){
	if(version_is_less( version: vers, test_version: "2.1.2" )){
		vuln = TRUE;
		fix = "2.1.2";
	}
}
if(IsMatchRegexp( vers, "^2\\.2" )){
	if(version_is_less( version: vers, test_version: "2.2.2" )){
		vuln = TRUE;
		fix = "2.2.2";
	}
}
if(vuln){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

