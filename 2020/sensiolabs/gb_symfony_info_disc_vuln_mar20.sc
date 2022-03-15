if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112720" );
	script_version( "2021-07-08T11:00:45+0000" );
	script_tag( name: "last_modification", value: "2021-07-08 11:00:45 +0000 (Thu, 08 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-04-01 09:28:11 +0000 (Wed, 01 Apr 2020)" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-01 20:34:00 +0000 (Wed, 01 Apr 2020)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2020-5274" );
	script_name( "Symfony 4.4.x < 4.4.4, 5.0.x < 5.0.4 Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_symfony_consolidation.sc" );
	script_mandatory_keys( "symfony/detected" );
	script_tag( name: "summary", value: "Symfony is prone to an information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "When ErrorHandler renders an exception HTML page, it uses un-escaped
  properties from the related Exception class to render the stacktrace. The security issue comes from the
  fact that the stacktraces were also displayed in non-debug environments." );
	script_tag( name: "affected", value: "Symfony versions 4.4.0 to 4.4.3 and 5.0.0 to 5.0.3." );
	script_tag( name: "solution", value: "The issues have been fixed in Symfony 4.4.4 and 5.0.4." );
	script_xref( name: "URL", value: "https://github.com/symfony/symfony/security/advisories/GHSA-m884-279h-32v2" );
	exit( 0 );
}
CPE = "cpe:/a:sensiolabs:symfony";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_in_range( version: version, test_version: "4.4.0", test_version2: "4.4.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.4.4", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.0.0", test_version2: "5.0.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.0.4", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

