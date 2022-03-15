CPE = "cpe:/a:apache:activemq";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807971" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2016-0734" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-05-05 17:11:01 +0530 (Thu, 05 May 2016)" );
	script_name( "Apache ActiveMQ Clickjacking Vulnerability May16" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_activemq_consolidation.sc" );
	script_mandatory_keys( "apache/activemq/detected" );
	script_xref( name: "URL", value: "https://activemq.apache.org/security-advisories.data/CVE-2016-0734-announcement.txt" );
	script_tag( name: "summary", value: "Apache ActiveMQ is prone to a clickjacking vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as the web-based administration console does not set an
  X-Frame-Options header in HTTP responses." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct clickjacking attacks via a crafted web page." );
	script_tag( name: "affected", value: "Apache ActiveMQ Version 5.x before 5.13.2." );
	script_tag( name: "solution", value: "Upgrade to Apache ActiveMQ Version 5.13.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!appVer = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_in_range( version: appVer, test_version: "5.0.0", test_version2: "5.13.1" )){
	report = report_fixed_ver( installed_version: appVer, fixed_version: "5.13.2" );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

