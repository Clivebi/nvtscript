if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809301" );
	script_version( "2021-02-10T08:19:07+0000" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-02-10 08:19:07 +0000 (Wed, 10 Feb 2021)" );
	script_tag( name: "creation_date", value: "2016-09-12 13:20:02 +0530 (Mon, 12 Sep 2016)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "Oracle MySQL Unspecified Vulnerability-03 Sep16 (Linux)" );
	script_tag( name: "summary", value: "This host is running Oracle MySQL and is
  prone to an unspecified vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple errors exist. Please see the references for more information." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  remote attacker to gain elevated privileges on the affected system, also
  could allow buffer overflow attacks." );
	script_tag( name: "affected", value: "Oracle MySQL Server 5.5.x to 5.5.51
  on Linux" );
	script_tag( name: "solution", value: "Upgrade to Oracle MySQL Server 5.5.52 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-52.html" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Databases" );
	script_dependencies( "mysql_version.sc", "os_detection.sc" );
	script_mandatory_keys( "oracle/mysql/detected", "Host/runs_unixoide" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
CPE = "cpe:/a:oracle:mysql";
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(IsMatchRegexp( vers, "^5\\.5\\." )){
	if(version_in_range( version: vers, test_version: "5.5", test_version2: "5.5.51" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "5.5.52", install_path: path );
		security_message( data: report, port: port );
		exit( 0 );
	}
}

