CPE = "cpe:/a:tiki:tikiwiki_cms/groupware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108064" );
	script_version( "2021-09-16T14:01:49+0000" );
	script_cve_id( "CVE-2016-10143" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-16 14:01:49 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-03-14 01:59:00 +0000 (Tue, 14 Mar 2017)" );
	script_tag( name: "creation_date", value: "2017-01-30 16:00:00 +0100 (Mon, 30 Jan 2017)" );
	script_name( "Tiki Wiki CMS Groupware 'fixedURLData' Local File Inclusion Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_tikiwiki_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "TikiWiki/installed" );
	script_xref( name: "URL", value: "http://tiki.org/article445-Security-updates-Tiki-16-2-15-4-and-Tiki-12-11-released" );
	script_xref( name: "URL", value: "https://sourceforge.net/p/tikiwiki/code/60308/" );
	script_tag( name: "summary", value: "The host is installed with Tiki Wiki CMS Groupware
  and is prone to a local file inclusion vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The Flaw is due to improper sanitization
  of input passed to the 'fixedURLData' parameter of the 'display_banner.php' script." );
	script_tag( name: "impact", value: "Successful exploitation will allow an user having access to the
  admin backend to gain access to arbitrary files and to compromise the application." );
	script_tag( name: "affected", value: "Tiki Wiki CMS Groupware versions:

  - below 12.11 LTS

  - 13.x, 14.x and 15.x below 15.4" );
	script_tag( name: "solution", value: "Upgrade to Tiki Wiki CMS Groupware version 12.11 LTS, 15.4 or
  later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://tiki.org" );
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
if(version_is_less( version: vers, test_version: "12.11" )){
	vuln = TRUE;
	fix = "12.11";
}
if(version_in_range( version: vers, test_version: "13", test_version2: "15.3" )){
	vuln = TRUE;
	fix = "15.4";
}
if(vuln){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

