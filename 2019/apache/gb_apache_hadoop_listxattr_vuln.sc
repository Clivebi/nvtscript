CPE = "cpe:/a:apache:hadoop";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141986" );
	script_version( "2021-09-06T12:43:44+0000" );
	script_tag( name: "last_modification", value: "2021-09-06 12:43:44 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-02-12 10:35:05 +0700 (Tue, 12 Feb 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-02-21 17:13:00 +0000 (Thu, 21 Feb 2019)" );
	script_cve_id( "CVE-2018-1296" );
	script_bugtraq_id( 106764 );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_name( "Apache Hadoop HDFS Permissive listXAttr Authorization" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_hadoop_detect.sc" );
	script_mandatory_keys( "Apache/Hadoop/Installed" );
	script_tag( name: "summary", value: "HDFS exposes extended attribute key/value pairs during listXAttrs, verifying
only path-level search access to the directory rather than path-level read permission to the referent. This
affects features that store sensitive data in extended attributes, such as HDFS encryption secrets." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host" );
	script_tag( name: "affected", value: "Apache Hadoop 3.0.0-alpha1 to 3.0.0, 2.9.0, 2.8.0 to 2.8.3 and 2.5.0 to
2.7.5." );
	script_tag( name: "solution", value: "If a file contains sensitive data in extended attributes, users and admins
need to change the permission to prevent others from listing the directory which contains the file." );
	script_xref( name: "URL", value: "https://lists.apache.org/thread.html/a5b15bc76fbdad2ee40761aacf954a13aeef67e305f86d483f267e8e@%3Cuser.hadoop.apache.org%3E" );
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
if(version_in_range( version: version, test_version: "2.5.0", test_version2: "2.7.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "2.8.0", test_version2: "2.8.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_is_equal( version: version, test_version: "2.9.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_is_equal( version: version, test_version: "3.0.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

