CPE = "cpe:/a:phpmyadmin:phpmyadmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108123" );
	script_version( "2021-09-17T08:01:48+0000" );
	script_tag( name: "last_modification", value: "2021-09-17 08:01:48 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-04-10 12:18:02 +0200 (Mon, 10 Apr 2017)" );
	script_tag( name: "cvss_base", value: "3.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:S/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-01 01:29:00 +0000 (Sat, 01 Jul 2017)" );
	script_cve_id( "CVE-2016-4412" );
	script_bugtraq_id( 94519 );
	script_name( "phpMyAdmin CVE-2016-4412 Open Redirection Vulnerability (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_phpmyadmin_detect_900129.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpMyAdmin/installed", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "phpMyAdmin is prone to an open redirection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "A user can be tricked into following a link leading to phpMyAdmin, which after
  authentication redirects to another malicious site. The attacker must sniff the user's valid phpMyAdmin token." );
	script_tag( name: "affected", value: "phpMyAdmin 4.0.x prior to 4.0.10.16." );
	script_tag( name: "solution", value: "Update to version 4.0.10.16 or later." );
	script_xref( name: "URL", value: "https://www.phpmyadmin.net/security/PMASA-2016-57" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/94519" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(IsMatchRegexp( vers, "^4\\.0\\." )){
	if(version_is_less( version: vers, test_version: "4.0.10.16" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "4.0.10.16" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

