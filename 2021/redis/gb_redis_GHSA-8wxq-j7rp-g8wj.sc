CPE = "cpe:/a:redis:redis";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146369" );
	script_version( "2021-08-24T09:01:06+0000" );
	script_tag( name: "last_modification", value: "2021-08-24 09:01:06 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-07-23 08:54:20 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-30 16:28:00 +0000 (Fri, 30 Jul 2021)" );
	script_cve_id( "CVE-2021-32761" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Redis Integer Overflow Vulnerability (GHSA-8wxq-j7rp-g8wj)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "gb_redis_detect.sc" );
	script_mandatory_keys( "redis/installed" );
	script_tag( name: "summary", value: "Redis is prone to an integer overflow vulnerability." );
	script_tag( name: "insight", value: "On 32-bit versions, Redis BITFIELD command is vulnerable to
  integer overflow that can potentially be exploited to corrupt the heap, leak arbitrary heap
  contents or trigger remote code execution. The vulnerability involves constructing specially
  crafted bit commands which overflow the bit offset." );
	script_tag( name: "affected", value: "Redis version 2.2 and later.

  This problem only affects 32-bit versions of Redis." );
	script_tag( name: "solution", value: "Update to version 5.0.13, 6.0.15, 6.2.5 or later." );
	script_xref( name: "URL", value: "https://github.com/redis/redis/security/advisories/GHSA-8wxq-j7rp-g8wj" );
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
if(version_in_range( version: version, test_version: "2.2", test_version2: "5.0.12" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.0.13" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "6.0", test_version2: "6.0.14" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.0.15" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "6.2", test_version2: "6.2.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.2.5" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

