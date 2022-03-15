CPE = "cpe:/a:mantisbt:mantisbt";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806032" );
	script_version( "2019-07-05T10:41:31+0000" );
	script_cve_id( "CVE-2014-8987" );
	script_bugtraq_id( 71184 );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2019-07-05 10:41:31 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2015-09-01 12:57:59 +0530 (Tue, 01 Sep 2015)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "MantisBT Cross Site Scripting Vulnerability September15 (Linux)" );
	script_tag( name: "summary", value: "This host is running MantisBT and is prone
  to cross site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to MantisBT Configuration
  Report page 'adm_config_report.php' did not escape a parameter before
  displaying it on the page." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers remote attackers to inject arbitrary web script or HTML via the
  'config_option' parameter." );
	script_tag( name: "affected", value: "MantisBT versions 1.2.13 through 1.2.17
  on Linux" );
	script_tag( name: "solution", value: "Upgrade to version 1.2.18 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.mantisbt.org/bugs/view.php?id=17870" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2014/11/14/9" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "mantis_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "mantisbt/detected", "Host/runs_unixoide" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!mantisPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!mantisVer = get_app_version( cpe: CPE, port: mantisPort )){
	exit( 0 );
}
if(version_in_range( version: mantisVer, test_version: "1.2.13", test_version2: "1.2.17" )){
	report = report_fixed_ver( installed_version: mantisVer, fixed_version: "1.2.18" );
	security_message( port: mantisPort, data: report );
	exit( 0 );
}
exit( 99 );

