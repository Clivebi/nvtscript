CPE = "cpe:/a:roundcube:webmail";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108023" );
	script_version( "2019-09-10T11:55:44+0000" );
	script_cve_id( "CVE-2016-9920" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2019-09-10 11:55:44 +0000 (Tue, 10 Sep 2019)" );
	script_tag( name: "creation_date", value: "2016-12-07 13:00:00 +0100 (Wed, 07 Dec 2016)" );
	script_name( "Roundcube Webmail Remote Code Execution Vulnerability via mail()" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "sw_roundcube_detect.sc" );
	script_mandatory_keys( "roundcube/detected" );
	script_tag( name: "summary", value: "This host is installed with Roundcube Webmail and is prone to
  a remote code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote authenticated
  attackers to execute arbitrary code on the host." );
	script_tag( name: "affected", value: "Roundcube Webmail versions prior to 1.1.7 and 1.2.x prior to 1.2.3 if:

  - the PHP mail() function is used

  - PHP mail() is configured to use sendmail

  - PHP safe_mode is turned off" );
	script_tag( name: "solution", value: "Upgrade Roundcube Webmail to 1.1.7 or 1.2.3." );
	script_xref( name: "URL", value: "https://blog.ripstech.com/2016/roundcube-command-execution-via-email/" );
	script_xref( name: "URL", value: "https://roundcube.net/news/2016/11/28/updates-1.2.3-and-1.1.7-released" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
path = infos["location"];
if(version_is_less( version: version, test_version: "1.1.7" ) || version_in_range( version: version, test_version: "1.2.0", test_version2: "1.2.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.1.7/1.2.3", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

