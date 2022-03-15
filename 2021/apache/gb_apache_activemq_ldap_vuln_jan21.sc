CPE = "cpe:/a:apache:activemq";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145275" );
	script_version( "2021-08-24T09:01:06+0000" );
	script_tag( name: "last_modification", value: "2021-08-24 09:01:06 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-01-29 03:37:08 +0000 (Fri, 29 Jan 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_cve_id( "CVE-2021-26117" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Apache ActiveMQ < 5.15.14, 5.16.0 < 5.16.1 Anonymous Bind Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_activemq_consolidation.sc" );
	script_mandatory_keys( "apache/activemq/detected" );
	script_tag( name: "summary", value: "Apache ActiveMQ is prone to an anonymous bind vulnerability in the
  optional ActiveMQ LDAP login module." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The optional ActiveMQ LDAP login module can be configured to use anonymous
  access to the LDAP server. In this case the anonymous context is used to verify a valid users password in
  error, resulting in no check on the password." );
	script_tag( name: "affected", value: "Apache ActiveMQ prior to version 5.15.14 or 5.16.1." );
	script_tag( name: "solution", value: "Upgrade to version 5.15.14, 5.16.1 or later. As a mitigation don't use
  anonymous binds in the LDAP configuration." );
	script_xref( name: "URL", value: "https://lists.apache.org/thread.html/re1b98da90a5f2e1c2e2d50e31c12e2578d61fe01c0737f9d0bd8de99@%3Cannounce.apache.org%3E" );
	script_xref( name: "URL", value: "https://issues.apache.org/jira/browse/AMQ-8035" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "5.15.14" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.15.14" );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(version_is_equal( version: version, test_version: "5.16.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.16.1" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

