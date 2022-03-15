CPE = "cpe:/a:symantec:web_gateway";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105142" );
	script_bugtraq_id( 71620 );
	script_cve_id( "CVE-2014-7285" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_version( "2021-09-07T06:04:54+0000" );
	script_name( "Symantec Web Gateway Command Injection Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/71620" );
	script_xref( name: "URL", value: "http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2014&suid=20141216_00" );
	script_tag( name: "impact", value: "Successfully exploiting this issue may allow an attacker to execute
  arbitrary OS commands in the context of the affected appliance." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Symantec was notified of an OS command injection vulnerability in PHP
  script which impacts the SWG management console.  The results of successful exploitation could potentially
  range from unauthorized disclosure of sensitive data to possible unauthorized access to the Symantec Web
  Gateway Appliance." );
	script_tag( name: "solution", value: "Updatei to 5.2.2 or higher." );
	script_tag( name: "summary", value: "Symantec Web Gateway is prone to a command-injection vulnerability." );
	script_tag( name: "affected", value: "Versions prior to Symantec Web Gateway 5.2.2 are vulnerable." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-07 06:04:54 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2014-12-18 10:41:05 +0100 (Thu, 18 Dec 2014)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_symantec_web_gateway_detect.sc" );
	script_mandatory_keys( "symantec_web_gateway/installed" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(vers = get_app_version( cpe: CPE, port: port )){
	if(version_is_less( version: vers, test_version: "5.2.2" )){
		report = "Installed version: " + vers + "\nFixed version:     5.2.2";
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

