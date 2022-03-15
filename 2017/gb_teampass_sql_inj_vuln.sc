CPE = "cpe:/a:teampass:teampass";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112143" );
	script_version( "2021-09-16T08:01:42+0000" );
	script_cve_id( "CVE-2017-9436" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-16 08:01:42 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-06-13 16:56:00 +0000 (Tue, 13 Jun 2017)" );
	script_tag( name: "creation_date", value: "2017-11-28 09:01:00 +0100 (Tue, 28 Nov 2017)" );
	script_name( "TeamPass SQL Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_teampass_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "teampass/installed" );
	script_xref( name: "URL", value: "https://github.com/nilsteampassnet/TeamPass/blob/master/changelog.md" );
	script_tag( name: "summary", value: "This host is installed with TeamPass and
  is prone to an sql injection vulnerability in users.queries.php." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker to read sensitive data and/or modify database data." );
	script_tag( name: "affected", value: "TeamPass before version 2.1.27.4." );
	script_tag( name: "solution", value: "Upgrade to TeamPass 2.1.27.4 or later." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://teampass.net/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "2.1.27.4" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.1.27.4" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

