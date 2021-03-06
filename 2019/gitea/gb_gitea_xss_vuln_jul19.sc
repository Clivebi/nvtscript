CPE = "cpe:/a:gitea:gitea";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114116" );
	script_version( "2021-09-08T09:01:34+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 09:01:34 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-07-30 14:12:11 +0200 (Tue, 30 Jul 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-12 17:03:00 +0000 (Fri, 12 Jul 2019)" );
	script_cve_id( "CVE-2019-1010314" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Gitea 1.7.2 and 1.7.3 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_gitea_detect.sc" );
	script_mandatory_keys( "gitea/detected" );
	script_tag( name: "summary", value: "Gitea is prone to a cross-site scripting vulnerability
  in the repository's description." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute
  JavaScript in the victim's browser, when the vulnerable repository page is being loaded." );
	script_tag( name: "affected", value: "Gitea versions 1.7.2 and 1.7.3." );
	script_tag( name: "solution", value: "Update to version 1.7.4 or later." );
	script_xref( name: "URL", value: "https://github.com/go-gitea/gitea/releases/tag/v1.7.4" );
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
path = infos["location"];
if(version == "1.7.2" || version == "1.7.3"){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.7.4", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

