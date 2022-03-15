CPE = "cpe:/a:gitea:gitea";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145586" );
	script_version( "2021-08-26T14:01:06+0000" );
	script_tag( name: "last_modification", value: "2021-08-26 14:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-03-17 02:54:50 +0000 (Wed, 17 Mar 2021)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-18 19:34:00 +0000 (Thu, 18 Mar 2021)" );
	script_cve_id( "CVE-2021-28378" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Gitea 1.12.0 < 1.13.4 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_gitea_detect.sc" );
	script_mandatory_keys( "gitea/detected" );
	script_tag( name: "summary", value: "Gitea is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Gitea allows XSS via certain issue data in some situations." );
	script_tag( name: "affected", value: "Gitea versions 1.12.0 through 1.13.3." );
	script_tag( name: "solution", value: "Update to version 1.13.4 or later." );
	script_xref( name: "URL", value: "https://blog.gitea.io/2021/03/gitea-1.13.4-is-released/" );
	script_xref( name: "URL", value: "https://github.com/go-gitea/gitea/pull/14898" );
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
if(version_in_range( version: version, test_version: "1.12.0", test_version2: "1.13.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.13.4", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

