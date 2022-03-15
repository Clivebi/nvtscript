CPE = "cpe:/a:sonatype:nexus";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140611" );
	script_version( "2021-09-10T14:01:42+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 14:01:42 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-12-19 14:09:00 +0700 (Tue, 19 Dec 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-04 15:40:00 +0000 (Thu, 04 Jan 2018)" );
	script_cve_id( "CVE-2017-17717" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Sonatype Nexus Repository Manager Weak Password Encryption Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_sonatype_nexus_detect.sc" );
	script_mandatory_keys( "nexus/installed" );
	script_tag( name: "summary", value: "Sonatype Nexus Repository Manager has weak password encryption with a
hardcoded CMMDwoV value in the LDAP integration feature." );
	script_tag( name: "insight", value: "he Nexus Repository Manager stores the LDAP bind password in an on-disk
file using PBE with only 23 iterations and a hard-coded and weak password. Therefore offering as much protection
as a rot13 would." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Nexus Repository Manager version 2.x" );
	script_tag( name: "solution", value: "Update to a version from the 3.x series." );
	script_xref( name: "URL", value: "http://openwall.com/lists/oss-security/2017/12/17/3" );
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
if(version_is_less( version: version, test_version: "3.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.x" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

