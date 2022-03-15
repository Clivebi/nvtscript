CPE = "cpe:/a:nagios:nagiosxi";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800181" );
	script_version( "2020-04-24T07:24:50+0000" );
	script_tag( name: "last_modification", value: "2020-04-24 07:24:50 +0000 (Fri, 24 Apr 2020)" );
	script_tag( name: "creation_date", value: "2010-06-09 08:34:53 +0200 (Wed, 09 Jun 2010)" );
	script_cve_id( "CVE-2010-2111" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Pacific Timesheet Cross-Site Request Forgery Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/39951" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/58934" );
	script_xref( name: "URL", value: "http://cross-site-scripting.blogspot.com/2010/05/pacific-timesheet-674-cross-site.html" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_pacific_timesheet_detect.sc" );
	script_mandatory_keys( "pacifictimesheet/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to perform unauthorized
  actions." );
	script_tag( name: "affected", value: "Pacific Timesheet version 6.74 build 363." );
	script_tag( name: "insight", value: "The flaw is due to improper validation of user-supplied input.
  A remote attacker could exploit this vulnerability to perform cross-site
  request forgery by tricking a logged in administrator into visiting a
  malicious web site or link to perform unauthorized actions." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Update to version 6.75 or later." );
	script_tag( name: "summary", value: "This host is running Pacific Timesheet and is prone to cross-site
  request forgery vulnerability." );
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
location = infos["location"];
if(version_is_less_equal( version: version, test_version: "6.74.363" )){
	report = report_fixed_ver( installed_version: version, vulnerable_range: "Less or equal to 6.74.363", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

