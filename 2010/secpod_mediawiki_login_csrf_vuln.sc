CPE = "cpe:/a:mediawiki:mediawiki";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901109" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-04-29 10:04:32 +0200 (Thu, 29 Apr 2010)" );
	script_cve_id( "CVE-2010-1150" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_name( "MediaWiki Login CSRF Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_mediawiki_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "mediawiki/installed" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=580418" );
	script_xref( name: "URL", value: "https://bugzilla.wikimedia.org/show_bug.cgi?id=23076" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker cause CSRF attack and gain
  sensitive information." );
	script_tag( name: "affected", value: "MediaWiki version prior to 1.15.3

  MediaWiki version prior to 1.16.0beta2." );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of authenticated but unintended
  login attempt that allows attacker to conduct phishing attacks." );
	script_tag( name: "solution", value: "Upgrade to the latest version of MediaWiki 1.15.3 or later." );
	script_tag( name: "summary", value: "This host is running MediaWiki and is prone to Login CSRF vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "1.15.3" ) || version_in_range( version: vers, test_version: "1.6", test_version2: "1.16.0.beta1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.15.3 or 1.16.0.beta2" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

