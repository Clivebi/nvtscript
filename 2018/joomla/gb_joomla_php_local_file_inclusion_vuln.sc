CPE = "cpe:/a:joomla:joomla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813458" );
	script_version( "2021-06-15T02:00:29+0000" );
	script_cve_id( "CVE-2018-12712" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-15 02:00:29 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-20 15:47:00 +0000 (Mon, 20 Aug 2018)" );
	script_tag( name: "creation_date", value: "2018-06-27 16:36:27 +0530 (Wed, 27 Jun 2018)" );
	script_name( "Joomla! Core 'PHP' Local File Inclusion Vulnerability (20180601)" );
	script_tag( name: "summary", value: "This host is running Joomla and is prone
  local file inclusion vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error in PHP 5.3,
  where 'class_exists' function validates invalid names as valid." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct local file inclusion attacks." );
	script_tag( name: "affected", value: "Joomla core versions 2.5.0 through 3.8.8" );
	script_tag( name: "solution", value: "Upgrade to Joomla version 3.8.9 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://developer.joomla.org/security-centre/741-20180601-core-local-file-inclusion-with-php-5-3" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "joomla_detect.sc" );
	script_mandatory_keys( "joomla/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!jPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: jPort, exit_no_version: TRUE )){
	exit( 0 );
}
jVer = infos["version"];
path = infos["location"];
if(version_in_range( version: jVer, test_version: "2.5.0", test_version2: "3.8.8" )){
	report = report_fixed_ver( installed_version: jVer, fixed_version: "3.8.9", install_path: path );
	security_message( port: jPort, data: report );
	exit( 0 );
}
exit( 0 );

