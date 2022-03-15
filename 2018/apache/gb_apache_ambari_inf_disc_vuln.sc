if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113241" );
	script_version( "2021-06-15T02:00:29+0000" );
	script_tag( name: "last_modification", value: "2021-06-15 02:00:29 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-08-02 11:02:53 +0200 (Thu, 02 Aug 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2018-8042" );
	script_bugtraq_id( 104869 );
	script_name( "Apache Ambari >= 2.5.0, <= 2.6.2 Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_ambari_detect.sc" );
	script_mandatory_keys( "Apache/Ambari/Installed" );
	script_tag( name: "summary", value: "Apache Ambari is prone to an information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Hadoop credentials are stored in the Ambari Agent informational log." );
	script_tag( name: "impact", value: "Successful exploitation would allow an authenticated attacker to acquire users' Hadoop credentials." );
	script_tag( name: "affected", value: "Apache Ambari version 2.5.0 through 2.6.2." );
	script_tag( name: "solution", value: "Update to version 2.7.0." );
	script_xref( name: "URL", value: "https://cwiki.apache.org/confluence/display/AMBARI/Ambari+Vulnerabilities#AmbariVulnerabilities-CVE-2018-8042" );
	exit( 0 );
}
CPE = "cpe:/a:apache:ambari";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "2.5.0", test_version2: "2.6.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.7.0" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

