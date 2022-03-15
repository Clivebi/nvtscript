CPE = "cpe:/a:gogs:gogs";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141678" );
	script_version( "2021-06-15T02:54:56+0000" );
	script_tag( name: "last_modification", value: "2021-06-15 02:54:56 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-11-13 12:10:41 +0700 (Tue, 13 Nov 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-01-29 18:07:00 +0000 (Tue, 29 Jan 2019)" );
	script_cve_id( "CVE-2018-18925" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Gogs < 0.11.79 RCE Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_gogs_detect.sc" );
	script_mandatory_keys( "gogs/detected" );
	script_tag( name: "summary", value: "Gogs allows remote code execution because it does not properly validate
session IDs, as demonstrated by a '..' session-file forgery in the file session provider in file.go. This is
related to session ID handling in the go-macaron/session code for Macaron." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Gogs prior to version 0.11.79." );
	script_tag( name: "solution", value: "Update to version 0.11.79 or later." );
	script_xref( name: "URL", value: "https://github.com/gogs/gogs/issues/5469" );
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
if(version_is_less( version: version, test_version: "0.11.79" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "0.11.79" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

