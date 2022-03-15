CPE = "cpe:/a:roundcube:webmail";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114124" );
	script_version( "2019-09-10T11:55:44+0000" );
	script_tag( name: "last_modification", value: "2019-09-10 11:55:44 +0000 (Tue, 10 Sep 2019)" );
	script_tag( name: "creation_date", value: "2019-09-02 15:35:24 +0200 (Mon, 02 Sep 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2013-5645" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Roundcube Webmail < 0.9.3 Multiple XSS Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "sw_roundcube_detect.sc" );
	script_mandatory_keys( "roundcube/detected" );
	script_tag( name: "summary", value: "Roundcube Webmail is prone to multiple cross-site scripting vulnerabilities." );
	script_tag( name: "insight", value: "These XSS vulnerabilities allow user-assisted remote attackers to inject
  arbitrary web scripts or HTML via the body of a message visited in (1) new or (2) draft mode, related
  to compose.inc and (3) might allow remote authenticated users to inject arbitrary web scripts or HTML
  via an HTML signature, related to save_identity.inc." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Roundcube Webmail versions before 0.9.3." );
	script_tag( name: "solution", value: "Update to version 0.9.3, or later." );
	script_xref( name: "URL", value: "https://github.com/roundcube/roundcubemail/issues/4283" );
	script_xref( name: "URL", value: "https://github.com/roundcube/roundcubemail/wiki/Changelog#Release0.9.3" );
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
if(version_is_less( version: version, test_version: "0.8.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "0.8.1", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

