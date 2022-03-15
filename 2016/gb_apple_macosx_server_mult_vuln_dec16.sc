CPE = "cpe:/o:apple:os_x_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810232" );
	script_version( "2020-11-02T14:34:19+0000" );
	script_cve_id( "CVE-2013-3919", "CVE-2013-4854", "CVE-2014-0591", "CVE-2014-4424", "CVE-2014-4406", "CVE-2014-0060", "CVE-2014-0061", "CVE-2014-0062", "CVE-2014-0063", "CVE-2014-0064", "CVE-2014-0065", "CVE-2014-0066", "CVE-2014-4446", "CVE-2013-4164", "CVE-2013-6393", "CVE-2014-4447", "CVE-2014-3566" );
	script_bugtraq_id( 90690, 90689 );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2020-11-02 14:34:19 +0000 (Mon, 02 Nov 2020)" );
	script_tag( name: "creation_date", value: "2016-12-05 14:52:33 +0530 (Mon, 05 Dec 2016)" );
	script_name( "Apple OS X Server Multiple Vulnerabilities Dec16" );
	script_tag( name: "summary", value: "This host is installed with Apple OS X Server
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - an integer overflow issue existed in LibYAML's handling of YAML tags

  - the SSL protocol 3.0 uses nondeterministic CBC padding

  - an improper handling of credentials in Profile Manager

  - multiple errors in LibYAML

  - the SACL settings for Mail were cached and changes to the SACLs were not respected
  until after a restart of the Mail service

  - multiple errors in PostgreSQL

  - a cross-site scripting error existed in Xcode Server

  - a SQL injection issue existed in Wiki Server

  - multiple errors in BIND" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to obtain sensitive information, execute arbitrary commands and cause a denial of
  service condition." );
	script_tag( name: "affected", value: "Apple OS X Server before 4.0." );
	script_tag( name: "solution", value: "Upgrade to Apple OS X Server 4.0 or
  later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT203111" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_apple_macosx_server_detect.sc" );
	script_mandatory_keys( "Apple/OSX/Server/Version" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!serVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: serVer, test_version: "4.0" )){
	report = report_fixed_ver( installed_version: serVer, fixed_version: "4.0" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

