if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112506" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-02-05 11:16:13 +0100 (Tue, 05 Feb 2019)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-02-05 21:28:00 +0000 (Tue, 05 Feb 2019)" );
	script_cve_id( "CVE-2019-7325", "CVE-2019-7326", "CVE-2019-7327", "CVE-2019-7328", "CVE-2019-7329", "CVE-2019-7330", "CVE-2019-7331", "CVE-2019-7332", "CVE-2019-7333", "CVE-2019-7334", "CVE-2019-7335", "CVE-2019-7336", "CVE-2019-7337", "CVE-2019-7338", "CVE-2019-7339", "CVE-2019-7340", "CVE-2019-7341", "CVE-2019-7342", "CVE-2019-7343", "CVE-2019-7344", "CVE-2019-7345", "CVE-2019-7346", "CVE-2019-7347", "CVE-2019-7348", "CVE-2019-7349", "CVE-2019-7350", "CVE-2019-7351", "CVE-2019-7352" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "ZoneMinder < 1.34.0 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_zoneminder_detect.sc" );
	script_mandatory_keys( "zoneminder/installed" );
	script_tag( name: "summary", value: "ZoneMinder is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - Multiple self-stored, reflected and POST cross-site scripting (XSS) vulnerabilities.

  - Session fixation.

  - Cross-site request forgery.

  - Log injection.

  - A Time-of-check Time-of-use (TOCTOU) race condition." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to execute
  HTML or JavaScript code via multiple parameters, to access and modify records (add/delete Monitors, Users, etc.),
  to inject log messages, to hijack another user's account or to have other unspecified impact on the application and its host system." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to ZoneMinder version 1.34.0 or later." );
	script_xref( name: "URL", value: "https://github.com/ZoneMinder/zoneminder/releases" );
	exit( 0 );
}
CPE = "cpe:/a:zoneminder:zoneminder";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "1.34.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.34.0" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

