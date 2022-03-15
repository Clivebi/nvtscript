CPE = "cpe:/a:joomla:joomla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811042" );
	script_version( "2021-09-30T08:43:52+0000" );
	script_cve_id( "CVE-2017-7983", "CVE-2017-7986", "CVE-2017-7985" );
	script_bugtraq_id( 98016, 98024, 98020 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-30 08:43:52 +0000 (Thu, 30 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-05-03 12:20:00 +0000 (Wed, 03 May 2017)" );
	script_tag( name: "creation_date", value: "2017-05-15 15:21:09 +0530 (Mon, 15 May 2017)" );
	script_name( "Joomla! Information Disclosure and Cross-Site Scripting Vulnerabilities" );
	script_tag( name: "summary", value: "Joomla is prone to information disclosure and cross-site scripting vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Mail sent using the JMail API leaked the used PHPMailer version in the mail
    headers.

  - Inadequate filtering of specific HTML attributes.

  - Inadequate filtering of multibyte characters." );
	script_tag( name: "impact", value: "Successfully exploiting these issues allow
  remote attackers to gain access to potentially sensitive information and
  conduct cross-site scripting attacks." );
	script_tag( name: "affected", value: "Joomla core versions 1.5.0 through 3.6.5" );
	script_tag( name: "solution", value: "Upgrade to Joomla version 3.7.0 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://developer.joomla.org/security-centre/686-20170404-core-xss-vulnerability" );
	script_xref( name: "URL", value: "https://developer.joomla.org/security-centre/685-20170403-core-xss-vulnerability" );
	script_xref( name: "URL", value: "https://developer.joomla.org/security-centre/683-20170401-core-information-disclosure" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "joomla_detect.sc" );
	script_mandatory_keys( "joomla/installed" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!jPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!jVer = get_app_version( cpe: CPE, port: jPort )){
	exit( 0 );
}
if(version_in_range( version: jVer, test_version: "1.5.0", test_version2: "3.6.5" )){
	report = report_fixed_ver( installed_version: jVer, fixed_version: "3.7.0" );
	security_message( data: report, port: jPort );
	exit( 0 );
}
exit( 0 );

