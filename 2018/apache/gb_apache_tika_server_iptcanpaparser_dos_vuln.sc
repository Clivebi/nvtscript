CPE = "cpe:/a:apache:tika";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814053" );
	script_version( "2021-06-15T02:00:29+0000" );
	script_cve_id( "CVE-2018-8017" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-06-15 02:00:29 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-09-27 15:38:59 +0530 (Thu, 27 Sep 2018)" );
	script_name( "Apache Tika Server 'IptcAnpaParser' Denial of Service Vulnerability" );
	script_tag( name: "summary", value: "The host is installed with Apache Tika Server
  and is prone to denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is
  present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an improper validation
  for a crafted file in 'IptcAnpaParser'." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause a denial of service condition." );
	script_tag( name: "affected", value: "Apache Tika Server from versions 1.2 to 1.18" );
	script_tag( name: "solution", value: "Upgrade to Apache Tika Server 1.19 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://lists.apache.org/thread.html/72df7a3f0dda49a912143a1404b489837a11f374dfd1961061873a91@%3Cdev.tika.apache.org%3E" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_tika_server_detect.sc" );
	script_mandatory_keys( "Apache/Tika/Server/Installed" );
	script_require_ports( "Services/www", 9998, 80 );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!tPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: tPort, exit_no_version: TRUE )){
	exit( 0 );
}
tVer = infos["version"];
tPath = infos["location"];
if(version_in_range( version: tVer, test_version: "1.2", test_version2: "1.18" )){
	report = report_fixed_ver( installed_version: tVer, fixed_version: "1.19", install_path: tPath );
	security_message( data: report, port: tPort );
	exit( 0 );
}
exit( 0 );

