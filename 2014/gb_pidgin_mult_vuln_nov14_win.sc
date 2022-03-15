CPE = "cpe:/a:pidgin:pidgin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804890" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2014-3694", "CVE-2014-3695", "CVE-2014-3696", "CVE-2014-3697", "CVE-2014-3698" );
	script_bugtraq_id( 70701, 70702, 70705, 70704, 70703 );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-11-21 18:58:24 +0530 (Fri, 21 Nov 2014)" );
	script_name( "Pidgin Multiple Vulnerabilities Nov 2014 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Pidgin and is
  prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple errors exist due to:

  - An error when parsing XMPP messages.

  - An error when unpacking smiley themes.

  - Improper verification of the Basic Constraints of an SSL certificate.

  - An error when handling Groupwise message.

  - An error when handling of an MXit emoticon." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to cause a denial of service (crash), disclosure of potentially sensitive
  information, disclose and manipulate certain data and spoofing attacks." );
	script_tag( name: "affected", value: "Pidgin before version 2.10.10 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Pidgin version 2.10.10 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://pidgin.im/news/security/?id=86" );
	script_xref( name: "URL", value: "http://pidgin.im/news/security/?id=87" );
	script_xref( name: "URL", value: "http://pidgin.im/news/security/?id=88" );
	script_xref( name: "URL", value: "http://pidgin.im/news/security/?id=89" );
	script_xref( name: "URL", value: "http://pidgin.im/news/security/?id=90" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "secpod_pidgin_detect_win.sc" );
	script_mandatory_keys( "Pidgin/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "2.10.0", test_version2: "2.10.9" )){
	report = report_fixed_ver( installed_version: vers, vulnerable_range: "2.10.0 - 2.10.9" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

