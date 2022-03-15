CPE = "cpe:/a:mysql:mysql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808121" );
	script_version( "2020-08-24T11:37:53+0000" );
	script_cve_id( "CVE-2014-2494", "CVE-2014-4207" );
	script_bugtraq_id( 68579, 68593 );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 11:37:53 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-06-03 13:42:45 +0530 (Fri, 03 Jun 2016)" );
	script_name( "Oracle MySQL Multiple Unspecified Vulnerabilities-09 Jun16 (Linux)" );
	script_tag( name: "summary", value: "This host is running Oracle MySQL
  and is prone to multiple unspecified vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Unspecified errors in the MySQL
  Server component via unknown vectors related to ENARC and SROPTZR." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to manipulate certain data and cause a DoS (Denial of Service)." );
	script_tag( name: "affected", value: "Oracle MySQL version 5.5.37 and
  earlier on Linux." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/59521" );
	script_xref( name: "URL", value: "http://www.computerworld.com/s/article/9249690/Oracle_to_release_115_security_patches" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html#AppendixMSQL" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_dependencies( "mysql_version.sc", "os_detection.sc" );
	script_require_ports( "Services/mysql", 3306 );
	script_mandatory_keys( "MySQL/installed", "Host/runs_unixoide" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(IsMatchRegexp( vers, "^5\\.5" ) && version_in_range( version: vers, test_version: "5.5", test_version2: "5.5.37" )){
	report = report_fixed_ver( installed_version: vers, vulnerable_range: "5.5 - 5.5.37" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

