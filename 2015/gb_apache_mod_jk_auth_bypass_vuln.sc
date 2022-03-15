CPE = "cpe:/a:apache:mod_jk";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805612" );
	script_version( "2021-07-13T07:23:07+0000" );
	script_cve_id( "CVE-2014-8111" );
	script_bugtraq_id( 74265 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-13 07:23:07 +0000 (Tue, 13 Jul 2021)" );
	script_tag( name: "creation_date", value: "2015-05-11 12:56:25 +0530 (Mon, 11 May 2015)" );
	script_name( "Apache Tomcat JK Connector (mod_jk) < 1.2.41 Authentication Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_mod_jk_http_detect.sc" );
	script_mandatory_keys( "apache/mod_jk/detected" );
	script_xref( name: "URL", value: "https://cxsecurity.com/cveshow/CVE-2014-8111" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=1182591" );
	script_tag( name: "summary", value: "Apache Tomcat JK Connector (mod_jk) is prone to an
  authentication bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is triggered due to the incorrect handling of the
  JkMount and JkUnmount directives, which can lead to the exposure of a private artifact in a tree." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attacker to gain access
  to potentially sensitive information." );
	script_tag( name: "affected", value: "Apache Tomcat JK Connector (mod_jk) before 1.2.41." );
	script_tag( name: "solution", value: "Update to version 1.2.41 or later." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
path = infos["location"];
if(version_is_less_equal( version: version, test_version: "1.2.40" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.2.41", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

