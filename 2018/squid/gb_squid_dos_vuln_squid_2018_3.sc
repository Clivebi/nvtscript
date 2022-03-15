CPE = "cpe:/a:squid-cache:squid";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813402" );
	script_version( "2021-05-21T06:00:13+0200" );
	script_cve_id( "CVE-2018-1172" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-05-21 06:00:13 +0200 (Fri, 21 May 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:38:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-05-22 12:25:41 +0530 (Tue, 22 May 2018)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "Squid Proxy Cache Denial of Service Vulnerability (SQUID-2018:3)" );
	script_tag( name: "summary", value: "The host is installed with Squid and is
  prone to  denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to incorrect pointer
  handling." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause a denial of service." );
	script_tag( name: "affected", value: "Squid versions 3.1.12.2 through 3.1.23,
  3.2.0.8 through 3.2.14 and 3.3 through 4.0.12" );
	script_tag( name: "solution", value: "Upgrade to Squid version 4.0.13 or later.
  Patch and workaround is also available. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.squid-cache.org/Advisories/SQUID-2018_3.txt" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_squid_detect.sc" );
	script_mandatory_keys( "squid_proxy_server/installed" );
	script_require_ports( "Services/www", 3128, 8080 );
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
if(version_in_range( version: version, test_version: "3.1.12.2", test_version2: "3.1.23" ) || version_in_range( version: version, test_version: "3.2.0.8", test_version2: "3.2.14" ) || version_in_range( version: version, test_version: "3.3", test_version2: "4.0.12" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.0.13", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

