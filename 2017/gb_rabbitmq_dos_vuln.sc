CPE = "cpe:/a:pivotal_software:rabbitmq";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106499" );
	script_version( "2021-09-10T11:01:38+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 11:01:38 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-06 12:45:06 +0700 (Fri, 06 Jan 2017)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)" );
	script_cve_id( "CVE-2015-8786" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "RabbitMQ DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_rabbitmq_amqp_detect.sc" );
	script_mandatory_keys( "rabbitmq/amqp/installed" );
	script_tag( name: "summary", value: "RabbitMQ is prone to a denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "RabbitMQ allows remote authenticated users with certain
  privileges to cause a denial of service (resource consumption) via the 'lengths_age' or 'lengths_incr'
  parameter." );
	script_tag( name: "impact", value: "An authenticated attacker may cause a denial of service condition." );
	script_tag( name: "affected", value: "RabbitMQ before 3.6.1." );
	script_tag( name: "solution", value: "Update to version 3.6.1" );
	script_xref( name: "URL", value: "https://github.com/rabbitmq/rabbitmq-server/releases/tag/rabbitmq_v3_6_1" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "3.6.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.6.1" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

