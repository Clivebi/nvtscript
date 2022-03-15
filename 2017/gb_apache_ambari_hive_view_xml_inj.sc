CPE = "cpe:/a:apache:ambari";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108159" );
	script_version( "2021-09-14T12:01:45+0000" );
	script_tag( name: "last_modification", value: "2021-09-14 12:01:45 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-05-15 08:42:44 +0200 (Mon, 15 May 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-05-23 18:44:00 +0000 (Tue, 23 May 2017)" );
	script_cve_id( "CVE-2017-5654" );
	script_name( "Apache Ambari XML injection vulnerability in Hive View" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_ambari_detect.sc" );
	script_mandatory_keys( "Apache/Ambari/Installed" );
	script_xref( name: "URL", value: "https://cwiki.apache.org/confluence/display/AMBARI/Ambari+Vulnerabilities#AmbariVulnerabilities-FixedinAmbari2.4.3" );
	script_xref( name: "URL", value: "https://cwiki.apache.org/confluence/display/AMBARI/Ambari+Vulnerabilities#AmbariVulnerabilities-FixedinAmbari2.5.1" );
	script_tag( name: "summary", value: "This host is installed with Apache Ambari which is prone to a XML injection vulnerability." );
	script_tag( name: "impact", value: "An authorized user of the Ambari Hive View may be able to gain unauthorized read access to files on the host
  where the Amari server executes. Access to files are limit to the set of files for which the user that executes the Ambari server has read access." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Apache Ambari 2.4.x (before 2.4.3) and 2.5.0." );
	script_tag( name: "solution", value: "Upgrade to version 2.4.3/2.5.1 or later." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "2.4.0", test_version2: "2.4.2" ) || version_is_equal( version: vers, test_version: "2.5.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.4.3/2.5.1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

