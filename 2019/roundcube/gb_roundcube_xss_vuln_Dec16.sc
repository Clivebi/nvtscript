CPE = "cpe:/a:roundcube:webmail";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114128" );
	script_version( "2021-08-31T08:01:19+0000" );
	script_tag( name: "last_modification", value: "2021-08-31 08:01:19 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-09-03 15:18:28 +0200 (Tue, 03 Sep 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-01-18 02:59:00 +0000 (Wed, 18 Jan 2017)" );
	script_cve_id( "CVE-2016-4552" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Roundcube Webmail < 1.2.0 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "sw_roundcube_detect.sc" );
	script_mandatory_keys( "roundcube/detected" );
	script_tag( name: "summary", value: "Roundcube Webmail is prone to a cross-site scripting vulnerability." );
	script_tag( name: "insight", value: "This XSS vulnerability allows remote attackers to inject
  arbitrary web scripts or HTML via the href attribute in an area tag in an e-mail message." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Roundcube Webmail versions before 1.2.0." );
	script_tag( name: "solution", value: "Update to version 1.2.0, or later." );
	script_xref( name: "URL", value: "https://github.com/roundcube/roundcubemail/issues/5240" );
	script_xref( name: "URL", value: "https://github.com/roundcube/roundcubemail/wiki/Changelog#Release1.2.0" );
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
if(version_is_less( version: version, test_version: "1.2.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.2.0", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

