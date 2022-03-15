CPE = "cpe:/a:rconfig:rconfig";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143932" );
	script_version( "2021-07-07T02:00:46+0000" );
	script_tag( name: "last_modification", value: "2021-07-07 02:00:46 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-05-19 04:38:10 +0000 (Tue, 19 May 2020)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-18 20:42:00 +0000 (Mon, 18 May 2020)" );
	script_cve_id( "CVE-2020-12255", "CVE-2020-12256", "CVE-2020-12257", "CVE-2020-12258", "CVE-2020-12259" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "rConfig <= 3.9.5 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_rconfig_detect.sc" );
	script_mandatory_keys( "rconfig/detected" );
	script_tag( name: "summary", value: "rConfig is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "rConfig is prone to multiple vulnerabilities:

  - Remote code execution vulnerability due to improper validation in the file upload functionality (CVE-2020-12255)

  - Multiple XSS vulnerabilities (CVE-2020-12256, CVE-2020-12259)

  - CSRF vulnerability (CVE-2020-12257)

  - Session fixation vulnerability (CVE-2020-12258)" );
	script_tag( name: "affected", value: "rConfig version 3.9.5 and prior." );
	script_tag( name: "solution", value: "Update to version 3.9.6 or later." );
	script_xref( name: "URL", value: "https://www.rconfig.com/downloads/v3-release-notes" );
	script_xref( name: "URL", value: "https://gist.github.com/farid007/9f6ad063645d5b1550298c8b9ae953ff" );
	script_xref( name: "URL", value: "https://gist.github.com/farid007/8855031bad0e497264e4879efb5bc9f8" );
	script_xref( name: "URL", value: "https://gist.github.com/farid007/eb7310749520fb8cdf5942573c9954ef" );
	script_xref( name: "URL", value: "https://gist.github.com/farid007/8855031bad0e497264e4879efb5bc9f8" );
	script_xref( name: "URL", value: "https://gist.github.com/farid007/8855031bad0e497264e4879efb5bc9f8" );
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
location = infos["location"];
if(version_is_less_equal( version: version, test_version: "3.9.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.9.6", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

