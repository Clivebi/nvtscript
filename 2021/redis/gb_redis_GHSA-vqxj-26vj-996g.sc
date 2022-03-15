CPE = "cpe:/a:redis:redis";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145888" );
	script_version( "2021-08-24T09:01:06+0000" );
	script_tag( name: "last_modification", value: "2021-08-24 09:01:06 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-05-05 03:06:53 +0000 (Wed, 05 May 2021)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-09 09:15:00 +0000 (Fri, 09 Jul 2021)" );
	script_cve_id( "CVE-2021-29477" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Redis 6.0.x < 6.0.13, 6.2.x < 6.2.3 Integer Overflow Vulnerability (GHSA-vqxj-26vj-996g)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "gb_redis_detect.sc" );
	script_mandatory_keys( "redis/installed" );
	script_tag( name: "summary", value: "Redis is prone to an integer overflow vulnerability." );
	script_tag( name: "insight", value: "An integer overflow bug in Redis version 6.0 or newer could be
  exploited using the STRALGO LCS command to corrupt the heap and potentially result with remote
  code execution." );
	script_tag( name: "affected", value: "Redis version 6.0.x through 6.0.12 and 6.2.x through 6.2.2." );
	script_tag( name: "solution", value: "Update to version 6.0.13, 6.2.3 or later." );
	script_xref( name: "URL", value: "https://github.com/redis/redis/security/advisories/GHSA-vqxj-26vj-996g" );
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
if(version_in_range( version: version, test_version: "6.0", test_version2: "6.0.12" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.0.13" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "6.2", test_version2: "6.2.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.2.3" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

