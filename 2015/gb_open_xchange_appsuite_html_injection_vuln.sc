CPE = "cpe:/a:open-xchange:open-xchange_appsuite";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806072" );
	script_version( "2019-07-05T10:16:38+0000" );
	script_cve_id( "CVE-2013-7143" );
	script_bugtraq_id( 65013 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2019-07-05 10:16:38 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2015-10-06 12:24:33 +0530 (Tue, 06 Oct 2015)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Open-Xchange (OX) AppSuite HTML Injection Vulnerability Oct15" );
	script_tag( name: "summary", value: "The host is installed with
  Open-Xchange (OX) AppSuite and is prone to html injection vulnerability." );
	script_tag( name: "vuldetect", value: "Detect the installed version of
  Open-Xchange (OX) AppSuite with the help of detect nvt." );
	script_tag( name: "insight", value: "The flaw is due to it fails to properly
  sanitize user-supplied input." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attacker-supplied HTML and script code to run in the context of the affected
  browser, potentially allowing the attacker to steal cookie-based
  authentication credentials or control how the site is rendered to the user.
  Other attacks are also possible." );
	script_tag( name: "affected", value: "Open-Xchange (OX) AppSuite version 7.4.1" );
	script_tag( name: "solution", value: "Upgrade to Open-Xchange (OX) AppSuite
  version 7.4.1-rev7 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1029650" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/128257" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_ox_app_suite_detect.sc" );
	script_mandatory_keys( "open_xchange_appsuite/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!oxPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!oxVer = get_app_version( cpe: CPE, port: oxPort )){
	exit( 0 );
}
oxRev = get_kb_item( "open_xchange_appsuite/" + oxPort + "/revision" );
if(oxRev){
	oxVer = oxVer + "." + oxRev;
	if(version_in_range( version: oxVer, test_version: "7.4.1", test_version2: "7.4.1.6" )){
		report = "Installed Version: " + oxVer + "\nFixed Version:     7.4.1.7\n";
		security_message( port: oxPort, data: report );
		exit( 0 );
	}
}
exit( 99 );

