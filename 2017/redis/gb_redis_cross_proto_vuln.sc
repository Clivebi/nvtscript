CPE = "cpe:/a:redis:redis";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140459" );
	script_version( "2021-09-13T14:16:31+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 14:16:31 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-10-30 16:16:15 +0700 (Mon, 30 Oct 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-08 14:22:00 +0000 (Wed, 08 Aug 2018)" );
	script_cve_id( "CVE-2016-10517" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Redis Cross Protocol Scripting Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "gb_redis_detect.sc" );
	script_mandatory_keys( "redis/installed" );
	script_tag( name: "summary", value: "networking.c in Redis allows 'Cross Protocol Scripting' because it lacks a
check for POST and Host: strings, which are not valid in the Redis protocol (but commonly occur when an attack
triggers an HTTP request to the Redis TCP port)." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Redis 3.2.6 and prior." );
	script_tag( name: "solution", value: "Update to version 3.2.7 or later." );
	script_xref( name: "URL", value: "https://github.com/antirez/redis/commit/874804da0c014a7d704b3d285aa500098a931f50" );
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
if(version_is_less( version: version, test_version: "3.2.7" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.2.7" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

