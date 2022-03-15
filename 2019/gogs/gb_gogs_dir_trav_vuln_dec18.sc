if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112614" );
	script_version( "2021-09-29T12:07:39+0000" );
	script_tag( name: "last_modification", value: "2021-09-29 12:07:39 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-08-05 08:50:11 +0000 (Mon, 05 Aug 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-01-31 19:02:00 +0000 (Thu, 31 Jan 2019)" );
	script_cve_id( "CVE-2018-20303" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Gogs < 0.11.82.1218 Directory Traversal Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_gogs_detect.sc" );
	script_mandatory_keys( "gogs/detected" );
	script_tag( name: "summary", value: "Gogs is prone to a directory traversal vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to create a file under data/sessions
  on the server which can then lead to remote code execution and/or denial of service." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Gogs prior to version 0.11.82.1218." );
	script_tag( name: "solution", value: "Update to version 0.11.82.1218 or later." );
	script_xref( name: "URL", value: "https://github.com/gogs/gogs/issues/5558" );
	exit( 0 );
}
CPE = "cpe:/a:gogs:gogs";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
path = infos["location"];
if(version_is_less( version: version, test_version: "0.11.82.1218" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "0.11.82.1218", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

