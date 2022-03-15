CPE = "cpe:/a:apache:ambari";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108121" );
	script_version( "2021-09-16T14:01:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 14:01:49 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-04-06 07:42:44 +0200 (Thu, 06 Apr 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_cve_id( "CVE-2017-5642" );
	script_name( "Apache Ambari Insufficient ACLs during Installation" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_ambari_detect.sc" );
	script_mandatory_keys( "Apache/Ambari/Installed" );
	script_xref( name: "URL", value: "https://cwiki.apache.org/confluence/display/AMBARI/Ambari+Vulnerabilities#AmbariVulnerabilities-FixedinAmbari2.5.0" );
	script_xref( name: "URL", value: "https://github.com/apache/ambari/blob/release-2.5.0/ambari-server/src/main/resources/scripts/check_ambari_permissions.py" );
	script_tag( name: "summary", value: "Apache Ambari Server artifacts are not created with proper ACLs during the installation." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Apache Ambari 2.4.0 to 2.4.2" );
	script_tag( name: "solution", value: "Upgrade to version 2.5.0 which sets correct ACLs during the installation.

  Users of Version 2.4.0 through 2.4.2 may execute the check_ambari_permissions.py script found at the references to fix the
  permissions on Ambari server artifacts on the Ambari server host." );
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
if(version_in_range( version: vers, test_version: "2.4.0", test_version2: "2.4.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.5.0" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

