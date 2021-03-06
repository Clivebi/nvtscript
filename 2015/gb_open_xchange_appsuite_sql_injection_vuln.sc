CPE = "cpe:/a:open-xchange:open-xchange_appsuite";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806069" );
	script_version( "2019-07-05T10:16:38+0000" );
	script_cve_id( "CVE-2014-7871" );
	script_bugtraq_id( 70982 );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2019-07-05 10:16:38 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2015-10-05 16:02:56 +0530 (Mon, 05 Oct 2015)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Open-Xchange (OX) AppSuite SQL Injection Vulnerability Oct15" );
	script_tag( name: "summary", value: "The host is installed with
  Open-Xchange (OX) AppSuite and is prone to sql injection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to 'ExtractValue' function
  allows execution of arbitrary SQL code by passing it through MySQLs XPath
  interpreter." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  authenticated users to execute arbitrary SQL commands via a crafted
  'jslob API call'." );
	script_tag( name: "affected", value: "Open-Xchange (OX) AppSuite versions before
  7.4.2-rev36 and 7.6.x before 7.6.0-rev23" );
	script_tag( name: "solution", value: "Upgrade to Open-Xchange (OX) AppSuite
  version 7.4.2-rev36 or 7.6.0-rev23 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/129020" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/533936/100/0/threaded" );
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
oxVer = get_app_version( cpe: CPE, port: oxPort );
if(!oxVer || ContainsString( oxVer, "unknown" )){
	exit( 0 );
}
oxRev = get_kb_item( "open_xchange_appsuite/" + oxPort + "/revision" );
if(oxRev){
	oxVer = oxVer + "." + oxRev;
	if( version_is_less( version: oxVer, test_version: "7.4.2.36" ) ){
		fix = "7.4.2-rev36";
		VULN = TRUE;
	}
	else {
		if(IsMatchRegexp( oxVer, "^(7\\.6)" )){
			if(version_in_range( version: oxVer, test_version: "7.6.0", test_version2: "7.6.0.22" )){
				fix = "7.6.0-rev23";
				VULN = TRUE;
			}
		}
	}
	if(VULN){
		report = "Installed Version: " + oxVer + "\nFixed Version:     " + fix + "\n";
		security_message( port: oxPort, data: report );
		exit( 0 );
	}
}
exit( 99 );

