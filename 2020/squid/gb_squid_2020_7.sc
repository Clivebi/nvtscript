CPE = "cpe:/a:squid-cache:squid";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144212" );
	script_version( "2021-07-05T11:01:33+0000" );
	script_tag( name: "last_modification", value: "2021-07-05 11:01:33 +0000 (Mon, 05 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-07-03 05:56:38 +0000 (Fri, 03 Jul 2020)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-12 13:15:00 +0000 (Fri, 12 Mar 2021)" );
	script_cve_id( "CVE-2020-15049" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Squid Proxy Cache Security Update Advisory SQUID-2020:7" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_squid_detect.sc" );
	script_mandatory_keys( "squid_proxy_server/installed" );
	script_tag( name: "summary", value: "Squid is prone to a cache poisoning vulnerability." );
	script_tag( name: "insight", value: "Due to incorrect input validation Squid is vulnerable to a Request Smuggling
  and Poisoning attack against the HTTP cache." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Squid versions 2.0 - 2.STABLE9, 3.0 - 3.5.28, 4.0 - 4.11 and 5.0.1 - 5.0.2." );
	script_tag( name: "solution", value: "Update to version 4.12, 5.0.3 or later." );
	script_xref( name: "URL", value: "https://github.com/squid-cache/squid/security/advisories/GHSA-qf3v-rc95-96j5" );
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
if(IsMatchRegexp( version, "2\\." ) || version_in_range( version: version, test_version: "3.0", test_version2: "3.5.28" ) || version_in_range( version: version, test_version: "4.0", test_version2: "4.11" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.12" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.0.1", test_version2: "5.0.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.0.3" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

