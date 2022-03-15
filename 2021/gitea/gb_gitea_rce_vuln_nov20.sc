CPE = "cpe:/a:gitea:gitea";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145342" );
	script_version( "2021-08-26T14:01:06+0000" );
	script_tag( name: "last_modification", value: "2021-08-26 14:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-02-10 05:34:03 +0000 (Wed, 10 Feb 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-03 15:38:00 +0000 (Thu, 03 Dec 2020)" );
	script_cve_id( "CVE-2020-28991" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Gitea 0.9.99 < 1.12.6 RCE Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_gitea_detect.sc" );
	script_mandatory_keys( "gitea/detected" );
	script_tag( name: "summary", value: "Gitea does not prevent a git protocol path that specifies a TCP port number
  and also contains newlines (with URL encoding) in ParseRemoteAddr in modules/auth/repo_form.go." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Gitea versions 0.9.99 - 1.12.5." );
	script_tag( name: "solution", value: "Update to version 1.12.6 or later." );
	script_xref( name: "URL", value: "https://github.com/go-gitea/gitea/releases/tag/v1.12.6" );
	script_xref( name: "URL", value: "https://github.com/go-gitea/gitea/pull/13525" );
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
if(version_in_range( version: version, test_version: "0.9.99", test_version2: "1.12.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.12.6", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

