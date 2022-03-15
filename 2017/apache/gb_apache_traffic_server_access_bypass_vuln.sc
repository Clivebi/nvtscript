CPE = "cpe:/a:apache:traffic_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812230" );
	script_version( "2021-09-13T11:01:38+0000" );
	script_cve_id( "CVE-2015-3249" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-13 11:01:38 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-18 16:17:00 +0000 (Sat, 18 Nov 2017)" );
	script_tag( name: "creation_date", value: "2017-11-29 16:54:52 +0530 (Wed, 29 Nov 2017)" );
	script_name( "Apache Traffic Server (ATS) Access Bypass Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Apache Traffic
  Server and is prone to access bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to a failure to
  properly tunnel remap requests using CONNECT." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to bypass access restrictions." );
	script_tag( name: "affected", value: "Apache Traffic Server 5.1.x before 5.1.1" );
	script_tag( name: "solution", value: "Upgrade to Apache Wicket version 5.1.1
  or later." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_traffic_detect.sc" );
	script_mandatory_keys( "apache_trafficserver/installed" );
	script_xref( name: "URL", value: "https://issues.apache.org/jira/browse/TS-2677" );
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
atsVer = infos["version"];
atsPath = infos["location"];
if(IsMatchRegexp( atsVer, "^(5\\.1)" )){
	if(version_is_less( version: atsVer, test_version: "5.1.1" )){
		report = report_fixed_ver( installed_version: atsVer, fixed_version: "5.1.1", install_path: atsPath );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

