CPE = "cpe:/a:adminer:adminer";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108535" );
	script_version( "$Revision: 13169 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-01-20 14:26:42 +0100 (Sun, 20 Jan 2019) $" );
	script_tag( name: "creation_date", value: "2019-01-20 14:05:39 +0100 (Sun, 20 Jan 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Adminer 4.3.1 up to 4.6.2 File Disclosure Vulnerability (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_adminer_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "adminer/detected", "Host/runs_windows" );
	script_xref( name: "URL", value: "https://gwillem.gitlab.io/2019/01/17/adminer-4.6.2-file-disclosure-vulnerability/" );
	script_tag( name: "summary", value: "Adminer is prone to a File Disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Attackers can abuse this flaw to fetch sensitive files of the target system." );
	script_tag( name: "affected", value: "Adminer versions 4.3.1 up to 4.6.2. Other versions might be affected as well." );
	script_tag( name: "solution", value: "Update to version 4.6.3 or later which is reported to have fixed this vulnerability." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!info = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = info["version"];
if(version_in_range( version: vers, test_version: "4.3.1", test_version2: "4.6.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "4.6.3", install_path: info["location"] );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

