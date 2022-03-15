CPE = "cpe:/a:roundcube:webmail";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108097" );
	script_version( "2021-09-17T08:01:48+0000" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-17 08:01:48 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)" );
	script_tag( name: "creation_date", value: "2017-03-13 14:00:00 +0100 (Mon, 13 Mar 2017)" );
	script_bugtraq_id( 96817 );
	script_cve_id( "CVE-2017-6820" );
	script_name( "Roundcube Webmail CVE-2017-6820 Cross Site Scripting Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "sw_roundcube_detect.sc" );
	script_mandatory_keys( "roundcube/detected" );
	script_tag( name: "summary", value: "This host is installed with Roundcube Webmail and is prone to
  a Cross Site Scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site. This may allow
  the attacker to steal cookie-based authentication credentials and to launch other attacks." );
	script_tag( name: "affected", value: "Roundcube Webmail 1.2.x versions prior to 1.2.4 and 1.1.x
  versions prior to 1.1.8." );
	script_tag( name: "solution", value: "Upgrade Roundcube Webmail to 1.1.8 or 1.2.4." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/96817" );
	script_xref( name: "URL", value: "https://roundcube.net/news/2017/03/10/updates-1.2.4-and-1.1.8-released" );
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
if(version_in_range( version: version, test_version: "1.1", test_version2: "1.1.7" )){
	vuln = TRUE;
	fix = "1.1.8";
}
if(version_in_range( version: version, test_version: "1.2", test_version2: "1.2.3" )){
	vuln = TRUE;
	fix = "1.2.4";
}
if(vuln){
	report = report_fixed_ver( installed_version: version, fixed_version: fix, install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

