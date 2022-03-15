CPE = "cpe:/a:apache:activemq";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808146" );
	script_version( "2020-04-29T07:58:44+0000" );
	script_cve_id( "CVE-2016-3088" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-04-29 07:58:44 +0000 (Wed, 29 Apr 2020)" );
	script_tag( name: "creation_date", value: "2016-06-06 16:11:05 +0530 (Mon, 06 Jun 2016)" );
	script_name( "Apache ActiveMQ Arbitrary Code Execution Vulnerability June16" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_activemq_consolidation.sc" );
	script_mandatory_keys( "apache/activemq/detected" );
	script_xref( name: "URL", value: "http://activemq.apache.org/security-advisories.data/CVE-2016-3088-announcement.txt" );
	script_tag( name: "summary", value: "Apache ActiveMQ is prone to an arbitrary code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error in 'fileserver' web application, which does
  not validate 'HTTP PUT' and 'HTTP MOVE' requests properly." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to replace web application files with malicious code and perform remote code execution on the system." );
	script_tag( name: "affected", value: "Apache ActiveMQ Version 5.x to 5.13.2." );
	script_tag( name: "solution", value: "Upgrade to Apache ActiveMQ Version 5.14.0 or later." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!appVer = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_in_range( version: appVer, test_version: "5.0.0", test_version2: "5.13.2" )){
	report = report_fixed_ver( installed_version: appVer, fixed_version: "5.14.0" );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

