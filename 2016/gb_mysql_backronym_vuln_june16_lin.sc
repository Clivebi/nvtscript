if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808064" );
	script_version( "2021-02-10T08:19:07+0000" );
	script_cve_id( "CVE-2015-3152" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-02-10 08:19:07 +0000 (Wed, 10 Feb 2021)" );
	script_tag( name: "creation_date", value: "2016-06-02 17:05:55 +0530 (Thu, 02 Jun 2016)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "Oracle MySQL Backronym Vulnerability June16 (Linux)" );
	script_tag( name: "summary", value: "This host is running Oracle MySQL and is
  prone to an Backronym vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to improper validation
  of MySQL client library when establishing a secure connection to a MySQL
  server using the --ssl option." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  man-in-the-middle attackers to spoof servers via a cleartext-downgrade
  attack." );
	script_tag( name: "affected", value: "Oracle MySQL Server 5.7.2 and earlier
  on Linux." );
	script_tag( name: "solution", value: "Upgrade to version Oracle MySQL Server 5.7.3 or
  later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.ocert.org/advisories/ocert-2015-003.html" );
	script_xref( name: "URL", value: "https://duo.com/blog/backronym-mysql-vulnerability" );
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
if(version_is_less( version: vers, test_version: "5.7.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.7.3", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

