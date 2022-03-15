CPE = "cpe:/a:matomo:matomo";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108475" );
	script_version( "2020-12-28T14:44:29+0000" );
	script_tag( name: "last_modification", value: "2020-12-28 14:44:29 +0000 (Mon, 28 Dec 2020)" );
	script_tag( name: "creation_date", value: "2018-10-19 18:58:41 +0200 (Fri, 19 Oct 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Matomo Analytics < 3.6.1 'reportTitle' XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_matomo_detect.sc" );
	script_mandatory_keys( "matomo/installed" );
	script_xref( name: "URL", value: "https://github.com/matomo-org/matomo/pull/13502" );
	script_tag( name: "summary", value: "Matomo Analytics before version 3.6.1 is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "insight", value: "Matomo Analytics fails to ensure that the report title in an export overlay
  is escaped which could be used to inject and execute JavaScript." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Matomo Analytics before version 3.6.1." );
	script_tag( name: "solution", value: "Update to version 3.6.1 or later." );
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
path = info["location"];
if(version_is_less( version: vers, test_version: "3.6.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.6.1", install_url: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

