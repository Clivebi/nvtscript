CPE = "cpe:/a:apache:zookeeper";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143179" );
	script_version( "2021-09-02T13:01:30+0000" );
	script_tag( name: "last_modification", value: "2021-09-02 13:01:30 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-11-26 05:51:40 +0000 (Tue, 26 Nov 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_cve_id( "CVE-2019-0201" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Apache ZooKeeper Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_apache_zookeeper_detect.sc" );
	script_mandatory_keys( "apache/zookeeper/detected" );
	script_tag( name: "summary", value: "Apache ZooKeeper is prone to an information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "ZooKeeper's getACL() command doesn't check any permission when it retrieves the
  ACLs of the requested node and returns all information contained in the ACL Id field as plaintext string.
  DigestAuthenticationProvider overloads the Id field with the hash value that is used for user authentication. As
  a consequence, if Digest Authentication is in use, the unsalted hash value will be disclosed by getACL() request
  for unauthenticated or unprivileged users." );
	script_tag( name: "affected", value: "Apache ZooKeeper prior to version 3.4.14 and version 3.5.0-alpha to
  3.5.4-beta." );
	script_tag( name: "solution", value: "Update to version 3.4.14, 3.5.5 or later." );
	script_xref( name: "URL", value: "https://zookeeper.apache.org/security.html#CVE-2019-0201" );
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
if(version_is_less( version: version, test_version: "3.4.14" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.4.14" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "3.5.0", test_version2: "3.5.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.5.5" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

