if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112320" );
	script_version( "2021-06-15T02:00:29+0000" );
	script_tag( name: "last_modification", value: "2021-06-15 02:00:29 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-06-29 13:08:55 +0200 (Fri, 29 Jun 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2018-8016" );
	script_name( "Apache Cassandra < 3.11.2 Remote Code Execution Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_apache_cassandra_detect.sc" );
	script_mandatory_keys( "apache/cassandra/detected" );
	script_tag( name: "summary", value: "Apache Cassandra is prone to a remote code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The default configuration in Apache Cassandra 3.8 through 3.11.1 binds an unauthenticated JMX/RMI interface
  to all network interfaces, which allows remote attackers to execute arbitrary Java code via an RMI request." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to execute arbitrary code." );
	script_tag( name: "affected", value: "Apache Cassandra 3.8 through 3.11.1." );
	script_tag( name: "solution", value: "Update to version 3.11.2 or later." );
	script_xref( name: "URL", value: "https://issues.apache.org/jira/browse/CASSANDRA-14173" );
	exit( 0 );
}
CPE = "cpe:/a:apache:cassandra";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "3.8", test_version2: "3.11.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.11.2" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

