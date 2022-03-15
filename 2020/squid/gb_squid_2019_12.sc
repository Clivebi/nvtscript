CPE = "cpe:/a:squid-cache:squid";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143763" );
	script_version( "2021-07-05T11:01:33+0000" );
	script_tag( name: "last_modification", value: "2021-07-05 11:01:33 +0000 (Mon, 05 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-04-24 07:31:16 +0000 (Fri, 24 Apr 2020)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-11 14:43:00 +0000 (Thu, 11 Feb 2021)" );
	script_cve_id( "CVE-2019-12519", "CVE-2019-12521" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Squid Proxy Cache Security Update Advisory SQUID-2019:12" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_squid_detect.sc" );
	script_mandatory_keys( "squid_proxy_server/installed" );
	script_tag( name: "summary", value: "Squid is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "Squid is prone to multiple vulnerabilities:

  - Stack based buffer overflow vulnerability (CVE-2019-12519)

  - Heap buffer overflow vulnerability (CVE-2019-12521)" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Squid versions 3.x - 3.5.28, 4.x - 4.10, 5.x - 5.0.1." );
	script_tag( name: "solution", value: "Update to version 4.11, 5.0.2 or later." );
	script_xref( name: "URL", value: "http://www.squid-cache.org/Advisories/SQUID-2019_12.txt" );
	script_xref( name: "URL", value: "https://gitlab.com/jeriko.one/security/-/blob/master/squid/CVEs/CVE-2019-12519.txt" );
	script_xref( name: "URL", value: "https://gitlab.com/jeriko.one/security/-/blob/master/squid/CVEs/CVE-2019-12521.txt" );
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
if(version_in_range( version: version, test_version: "3.0", test_version2: "3.5.28" ) || version_in_range( version: version, test_version: "4.0", test_version2: "4.10" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.11" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.0", test_version2: "5.0.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.0.2" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

