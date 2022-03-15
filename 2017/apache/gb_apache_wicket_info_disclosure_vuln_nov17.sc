CPE = "cpe:/a:apache:wicket";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812103" );
	script_version( "2021-09-13T11:01:38+0000" );
	script_cve_id( "CVE-2014-3526" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-13 11:01:38 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-11 22:12:00 +0000 (Wed, 11 Dec 2019)" );
	script_tag( name: "creation_date", value: "2017-11-10 16:11:14 +0530 (Fri, 10 Nov 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Apache Wicket Information Disclosure Vulnerability Nov17" );
	script_tag( name: "summary", value: "This host is running Apache Wicket and is
  prone to information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as when storing the page
  markup at the server side Wicket uses as an identifier a pair of the current
  session id plus the new url. However, Wicket does not check if user session
  is temporary." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML." );
	script_tag( name: "affected", value: "Apache Wicket before 1.5.12, 6.x before 6.17.0,
  and 7.x before 7.0.0-M3" );
	script_tag( name: "solution", value: "Upgrade to Apache Wicket versions 1.5.12
  6.17.0, 7.0.0-M3 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://wicket.apache.org/news/2014/09/22/cve-2014-3526.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_wicket_detect.sc" );
	script_mandatory_keys( "Apache/Wicket/Installed" );
	script_require_ports( "Services/www", 8080 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!wkPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: wkPort, exit_no_version: TRUE )){
	exit( 0 );
}
wkVer = infos["version"];
wkpath = infos["location"];
if( version_is_less( version: wkVer, test_version: "1.5.12" ) ){
	fix = "1.5.12";
}
else {
	if( version_in_range( version: wkVer, test_version: "7.0", test_version2: "7.0.0.M2" ) ){
		fix = "7.0.0-M3";
	}
	else {
		if(IsMatchRegexp( wkVer, "^(6\\.)" )){
			if(version_is_less( version: wkVer, test_version: "6.17.0" )){
				fix = "6.17.0";
			}
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: wkVer, fixed_version: fix, install_path: wkpath );
	security_message( data: report, port: wkPort );
	exit( 0 );
}
exit( 0 );

