CPE = "cpe:/a:apache:ambari";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812875" );
	script_version( "2021-06-15T02:00:29+0000" );
	script_cve_id( "CVE-2018-8003" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-15 02:00:29 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-06-13 15:09:00 +0000 (Wed, 13 Jun 2018)" );
	script_tag( name: "creation_date", value: "2018-05-08 12:47:50 +0530 (Tue, 08 May 2018)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Apache Ambari Directory Traversal Vulnerability May18" );
	script_tag( name: "summary", value: "This host is running Apache Ambari and is
  prone to directory traversal vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to Apache Ambari unable
  to sanitize against a crafted HTTP request." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to craft an HTTP request which provides read-only access to any file on the
  filesystem of the host." );
	script_tag( name: "affected", value: "Apache Ambari versions from 1.4.0 through 2.6.1." );
	script_tag( name: "solution", value: "Upgrade to Apache Ambari version 2.6.2 or
  later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://cwiki.apache.org/confluence/display/AMBARI/Ambari+Vulnerabilities#AmbariVulnerabilities-CVE-2018-8003" );
	script_xref( name: "URL", value: "https://cwiki.apache.org/confluence/display/AMBARI/Installation+Guide+for+Ambari+2.6.2" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_ambari_detect.sc" );
	script_mandatory_keys( "Apache/Ambari/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!aport = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: aport, exit_no_version: TRUE )){
	exit( 0 );
}
aver = infos["version"];
apath = infos["location"];
if(version_in_range( version: aver, test_version: "1.4.0", test_version2: "2.6.1" )){
	report = report_fixed_ver( installed_version: aver, fixed_version: "2.6.2", install_path: apath );
	security_message( port: aport, data: report );
	exit( 0 );
}
exit( 0 );

