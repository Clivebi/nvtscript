CPE = "cpe:/a:oracle:webcenter_content";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812960" );
	script_version( "2021-06-30T02:00:35+0000" );
	script_cve_id( "CVE-2018-2596" );
	script_bugtraq_id( 102545 );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-06-30 02:00:35 +0000 (Wed, 30 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-03-06 12:17:44 +0530 (Tue, 06 Mar 2018)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "Oracle WebCenter Content Unspecified Vulnerability-02 (cpujan2018-3236628)" );
	script_tag( name: "summary", value: "The host is running Oracle WebCenter Content
  and is prone to an unspecified vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaws exist due to error in the 'Content
  Server' component." );
	script_tag( name: "impact", value: "Successful exploitation of this vulnerability
  can result in unauthorized creation, deletion or modification access to critical
  data or all Oracle WebCenter Content accessible data as well as unauthorized read
  access to a subset of Oracle WebCenter Content accessible data." );
	script_tag( name: "affected", value: "Oracle WebCenter Content version 11.1.1.9.0,
  12.2.1.2.0 and 12.2.1.3.0" );
	script_tag( name: "solution", value: "Apply the update from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_oracle_webcenter_content_detect.sc" );
	script_mandatory_keys( "Oracle/WebCenter/Content/Version" );
	script_require_ports( "Services/www", 80, 443 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!webPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: webPort, exit_no_version: TRUE )){
	exit( 0 );
}
webVer = infos["version"];
path = infos["location"];
affected = make_list( "11.1.1.9.0",
	 "12.2.1.2.0",
	 "12.2.1.3.0" );
for version in affected {
	if(webVer == version){
		report = report_fixed_ver( installed_version: webVer, fixed_version: "Apply the patch", install_path: path );
		security_message( port: webPort, data: report );
		exit( 0 );
	}
}
exit( 0 );

