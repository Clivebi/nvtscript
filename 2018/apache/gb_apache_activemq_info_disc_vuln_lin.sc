if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112224" );
	script_version( "2021-06-15T02:00:29+0000" );
	script_tag( name: "last_modification", value: "2021-06-15 02:00:29 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-15 14:50:00 +0100 (Thu, 15 Feb 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-05 19:15:00 +0000 (Fri, 05 Mar 2021)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2017-15709" );
	script_name( "Apache Active MQ 5.14.0 - 5.15.2 Information Disclosure Vulnerability (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_activemq_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "apache/activemq/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "Apache Active MQ is prone to an information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "The script checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "When using the OpenWire protocol it was found that certain system
  details (such as the OS and kernel version) are exposed as plain text." );
	script_tag( name: "affected", value: "Apache Active MQ 5.14.0 up to and including 5.15.2." );
	script_tag( name: "solution", value: "Update to Apache Active MQ 5.15.3 or later." );
	script_xref( name: "URL", value: "https://lists.apache.org/thread.html/2b6f04a552c6ec2de6563c2df3bba813f0fe9c7e22cce27b7829db89@%3Cdev.activemq.apache.org%3E" );
	exit( 0 );
}
CPE = "cpe:/a:apache:activemq";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.14.0", test_version2: "5.15.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.15.3" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

