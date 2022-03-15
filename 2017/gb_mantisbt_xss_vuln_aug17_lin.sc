CPE = "cpe:/a:mantisbt:mantisbt";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811722" );
	script_version( "2021-09-15T10:01:53+0000" );
	script_cve_id( "CVE-2015-2046" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-15 10:01:53 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-01 14:56:00 +0000 (Fri, 01 Sep 2017)" );
	script_tag( name: "creation_date", value: "2017-08-31 14:11:36 +0530 (Thu, 31 Aug 2017)" );
	script_name( "MantisBT 'adm_config_report.php' Cross-Site Scripting Vulnerability - Aug17 (Linux)" );
	script_tag( name: "summary", value: "This host is installed with MantisBT and is
  prone to cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as the 'adm_config_report.php'
  script does not validate input when handling the config file option before
  returning it to users." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to
  execute arbitrary script code in a user's browser session within the trust
  relationship between their browser and the server." );
	script_tag( name: "affected", value: "MantisBT version 1.2.13 through 1.2.19 on Linux" );
	script_tag( name: "solution", value: "Upgrade to MantisBT version 1.2.20 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "https://www.mantisbt.org/bugs/view.php?id=19301" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2015/02/21/2" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "mantis_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "mantisbt/detected", "Host/runs_unixoide" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!manPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!manVer = get_app_version( cpe: CPE, port: manPort )){
	exit( 0 );
}
if(version_in_range( version: manVer, test_version: "1.2.13", test_version2: "1.2.19" )){
	report = report_fixed_ver( installed_version: manVer, fixed_version: "1.2.20" );
	security_message( port: manPort, data: report );
	exit( 0 );
}
exit( 0 );

