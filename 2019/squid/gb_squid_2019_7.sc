CPE = "cpe:/a:squid-cache:squid";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143190" );
	script_version( "2021-08-27T13:01:16+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 13:01:16 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-11-27 06:37:52 +0000 (Wed, 27 Nov 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-11 00:15:00 +0000 (Sat, 11 Jul 2020)" );
	script_cve_id( "CVE-2019-12526", "CVE-2019-18678", "CVE-2019-12523", "CVE-2019-18676" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Squid Proxy Cache Multiple Security Update Advisories (SQUID-2019:7, SQUID-2019:8, SQUID-2019:10)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_squid_detect.sc" );
	script_mandatory_keys( "squid_proxy_server/installed" );
	script_tag( name: "summary", value: "Squid is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "Squid is prone to multiple vulnerabilities:

  - Heap Overflow issue in URN processing (CVE-2019-12526)

  - Multiple issues in URI processing (CVE-2019-18678, CVE-2019-18676)

  - HTTP Request Splitting issue in HTTP message processing (CVE-2019-18678)" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Squid versions 3.0 - 3.5.28 and 4.x - 4.8." );
	script_tag( name: "solution", value: "Update to version 4.9 or later." );
	script_xref( name: "URL", value: "http://www.squid-cache.org/Advisories/SQUID-2019_7.txt" );
	script_xref( name: "URL", value: "http://www.squid-cache.org/Advisories/SQUID-2019_8.txt" );
	script_xref( name: "URL", value: "http://www.squid-cache.org/Advisories/SQUID-2019_10.txt" );
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
if(version_in_range( version: version, test_version: "3.0", test_version2: "3.5.28" ) || version_in_range( version: version, test_version: "4.0", test_version2: "4.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.9" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );
