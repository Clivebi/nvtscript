CPE = "cpe:/a:squid-cache:squid";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143454" );
	script_version( "2021-07-05T11:01:33+0000" );
	script_tag( name: "last_modification", value: "2021-07-05 11:01:33 +0000 (Mon, 05 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-02-05 05:54:49 +0000 (Wed, 05 Feb 2020)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-04 20:47:00 +0000 (Thu, 04 Mar 2021)" );
	script_cve_id( "CVE-2019-12528", "CVE-2020-8449", "CVE-2020-8450", "CVE-2020-8517" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Squid Proxy Cache Multiple Security Update Advisories SQUID-2020:1, SQUID-2020:2, SQUID-2020:3" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_squid_detect.sc" );
	script_mandatory_keys( "squid_proxy_server/installed" );
	script_tag( name: "summary", value: "Squid is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "Squid is prone to multiple vulnerabilities:

  - Information Disclosure issue in FTP Gateway (CVE-2019-12528)

  - Improper Input Validation issues in HTTP Request processing (CVE-2020-8449, CVE-2020-8450)

  - Buffer Overflow issue in ext_lm_group_acl helper (CVE-2020-8517)" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Squid versions 2.x, 3.x - 3.5.28 and 4.x - 4.9." );
	script_tag( name: "solution", value: "Update to version 4.10 or later." );
	script_xref( name: "URL", value: "http://www.squid-cache.org/Advisories/SQUID-2020_1.txt" );
	script_xref( name: "URL", value: "http://www.squid-cache.org/Advisories/SQUID-2020_2.txt" );
	script_xref( name: "URL", value: "http://www.squid-cache.org/Advisories/SQUID-2020_3.txt" );
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
if(IsMatchRegexp( version, "^2\\." ) || version_in_range( version: version, test_version: "3.0", test_version2: "3.5.28" ) || version_in_range( version: version, test_version: "4.0", test_version2: "4.9" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.10" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

