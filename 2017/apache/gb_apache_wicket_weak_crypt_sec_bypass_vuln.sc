CPE = "cpe:/a:apache:wicket";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811841" );
	script_version( "2021-09-13T11:01:38+0000" );
	script_cve_id( "CVE-2014-7808" );
	script_bugtraq_id( 100946 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-13 11:01:38 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-24 18:19:00 +0000 (Tue, 24 Mar 2020)" );
	script_tag( name: "creation_date", value: "2017-10-04 13:06:12 +0530 (Wed, 04 Oct 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Apache Wicket 'CryptoMapper' Cross Site Request Forgery Vulnerability" );
	script_tag( name: "summary", value: "The host is installed with Apache Wicket
  and is prone to cross site request forgery vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to Wicket's default security
  settings of the usage of CryptoMapper to encrypt/obfuscate pages urls, which is not
  strong enough. It is possible to predict the encrypted version of an url based on
  the previous history." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to defeat a cryptographic protection mechanism and predict encrypted URLs by
  leveraging use of CryptoMapper as the default encryption provider." );
	script_tag( name: "affected", value: "Apache Wicket versions before 1.5.13, 6.x before
  6.19.0, and 7.x before 7.0.0-M5." );
	script_tag( name: "solution", value: "Upgrade to Apache Wicket 1.5.13 or 6.19.0
  or 7.0.0-M5 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.smrrd.de/cve-2014-7808-apache-wicket-csrf-2014.html" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_apache_wicket_detect.sc" );
	script_mandatory_keys( "Apache/Wicket/Installed" );
	script_require_ports( "Services/www", 8080 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
require("revisions-lib.inc.sc");
if(!Port = get_app_port( cpe: CPE )){
	exit( 0 );
}
Ver = get_app_version( cpe: CPE, port: Port );
if(!Ver){
	exit( 0 );
}
if( version_is_less( version: Ver, test_version: "1.5.13" ) ){
	fix = "1.5.13";
}
else {
	if( IsMatchRegexp( Ver, "^(6\\.)" ) ){
		if(version_is_less( version: Ver, test_version: "6.19.0" )){
			fix = "6.19.0";
		}
	}
	else {
		if(IsMatchRegexp( Ver, "^(7\\.)" ) && revcomp( a: Ver, b: "7.0.0.M5" ) < 0){
			fix = "7.0.0-M5";
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: Ver, fixed_version: fix );
	security_message( data: report, port: Port );
	exit( 0 );
}
exit( 0 );

