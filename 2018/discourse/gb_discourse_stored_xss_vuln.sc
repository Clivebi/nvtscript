if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112352" );
	script_version( "2021-09-29T12:07:39+0000" );
	script_tag( name: "last_modification", value: "2021-09-29 12:07:39 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "creation_date", value: "2018-08-08 09:46:25 +0200 (Wed, 08 Aug 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Discourse < 2.0.0 beta6 Stored XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_discourse_detect.sc" );
	script_mandatory_keys( "discourse/detected" );
	script_xref( name: "URL", value: "https://hackerone.com/reports/333507" );
	script_xref( name: "URL", value: "https://github.com/discourse/discourse/commit/4fb41663b3c7071dc1ef7d92eb3e5a6516dfe3b5" );
	script_tag( name: "summary", value: "Discourse is prone to a stored cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to steal cookies,
  passwords or to run arbitrary code on the victim's browser." );
	script_tag( name: "affected", value: "Discourse before version 2.0.0 beta6." );
	script_tag( name: "solution", value: "Update Discourse to version 2.0.0 beta6 or later." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
CPE = "cpe:/a:discourse:discourse";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
if(version_is_less( version: vers, test_version: "2.0.0" ) || version_in_range( version: vers, test_version: "2.0.0.beta1", test_version2: "2.0.0.beta5" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.0.0.beta6", install_path: infos["location"] );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

