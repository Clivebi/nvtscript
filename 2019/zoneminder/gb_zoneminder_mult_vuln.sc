if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112504" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-01-29 15:22:12 +0100 (Tue, 29 Jan 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_cve_id( "CVE-2019-6990", "CVE-2019-6991", "CVE-2019-6992", "CVE-2019-8423", "CVE-2019-8424", "CVE-2019-8425", "CVE-2019-8426", "CVE-2019-8427", "CVE-2019-8428", "CVE-2019-8429", "CVE-2019-13072" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "ZoneMinder <= 1.32.3 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_zoneminder_detect.sc" );
	script_mandatory_keys( "zoneminder/installed" );
	script_tag( name: "summary", value: "ZoneMinder is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - XSS vulnerability in web/skins/classic/views/zones.php (CVE-2019-6990).

  - Stack-based buffer overflow in the zmLoadUser() function in zm_user.cpp of the zmu binary (CVE-2018-6991).

  - stored-self XSS vulnerability in web/skins/classic/views/controlcaps.php (CVE-2019-6992).

  - SQL Injection via the skins/classic/views/events.php filter[Query][terms][0][cnj] parameter (CVE-2019-8423).

  - SQL Injection via the ajax/status.php sort parameter (CVE-2019-8424).

  - XSS in the construction of SQL-ERR messages (CVE-2019-8425).

  - XSS via the newControl array, as demonstrated by the newControl[MinTiltRange] parameter (CVE-2019-8426).

  - Command injection via shell metacharacters (CVE-2019-8427).

  - SQL Injection via the skins/classic/views/control.php groupSql parameter, as demonstrated by a newGroup[MonitorIds][] value (CVE-2019-8428).

  - SQL Injection via the ajax/status.php filter[Query][terms][0][cnj] parameter (CVE-2019-8429).

  - Stored XSS in the Filters page (Name field) (CVE-2019-13072)." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to execute code via a long username
  or execute HTML or JavaScript code via vulnerable fields." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Apply the provided patches." );
	script_xref( name: "URL", value: "https://github.com/ZoneMinder/zoneminder/issues/2444" );
	script_xref( name: "URL", value: "https://github.com/ZoneMinder/zoneminder/commit/a3e8fd4fd5b579865f35aac3b964bc78d5b7a94a" );
	script_xref( name: "URL", value: "https://github.com/ZoneMinder/zoneminder/issues/2478" );
	script_xref( name: "URL", value: "https://github.com/ZoneMinder/zoneminder/pull/2482" );
	script_xref( name: "URL", value: "https://github.com/ZoneMinder/zoneminder/commit/8c5687ca308e441742725e0aff9075779fa1a498" );
	script_xref( name: "URL", value: "https://github.com/ZoneMinder/zoneminder/issues/2445" );
	script_xref( name: "URL", value: "https://github.com/ZoneMinder/zoneminder/issues/2399" );
	script_xref( name: "URL", value: "https://github.com/ZoneMinder/zoneminder/issues/2642" );
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
if(version_is_less_equal( version: version, test_version: "1.32.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "Apply patches." );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

