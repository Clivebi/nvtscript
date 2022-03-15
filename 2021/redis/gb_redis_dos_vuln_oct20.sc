CPE = "cpe:/a:redis:redis";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145709" );
	script_version( "2021-08-24T09:01:06+0000" );
	script_tag( name: "last_modification", value: "2021-08-24 09:01:06 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-04-13 06:32:35 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-05 18:37:00 +0000 (Mon, 05 Apr 2021)" );
	script_cve_id( "CVE-2021-3470" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Redis Heap Overflow Vulnerability (Oct 2020)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "gb_redis_detect.sc" );
	script_mandatory_keys( "redis/installed" );
	script_tag( name: "summary", value: "Redis is prone to a heap overflow vulnerability." );
	script_tag( name: "insight", value: "A heap overflow issue was found in Redis when using a heap allocator other
  than jemalloc or glibc's malloc, leading to potential out of bound write or process crash. Effectively this
  flaw does not affect the vast majority of users, who use jemalloc or glibc malloc." );
	script_tag( name: "affected", value: "Redis versions 5.0.9 and prior and 6.x prior to 6.0.9." );
	script_tag( name: "solution", value: "Update to version 5.0.10, 6.0.9 or later." );
	script_xref( name: "URL", value: "https://github.com/redis/redis/pull/7963" );
	script_xref( name: "URL", value: "https://raw.githubusercontent.com/redis/redis/5.0.10/00-RELEASENOTES" );
	script_xref( name: "URL", value: "https://raw.githubusercontent.com/redis/redis/6.0.9/00-RELEASENOTES" );
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
if(version_is_less( version: version, test_version: "5.0.10" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.0.10" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "6.0", test_version2: "6.0.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.0.9" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

