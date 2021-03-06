CPE = "cpe:/a:open-xchange:open-xchange_appsuite";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806081" );
	script_version( "2019-07-05T10:16:38+0000" );
	script_cve_id( "CVE-2014-2078" );
	script_bugtraq_id( 71888 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-05 10:16:38 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2015-10-09 15:08:44 +0530 (Fri, 09 Oct 2015)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Open-Xchange AppSuite Email Configuration Information Disclosure Vulnerability" );
	script_tag( name: "summary", value: "The host is installed with
  Open-Xchange (OX) AppSuite and is prone to information disclosure
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to some error in E-Mail
  auto configuration." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to gain unauthorised access to other users data e.g. mail addresses." );
	script_tag( name: "affected", value: "Open-Xchange (OX) AppSuite version 7.4.2" );
	script_tag( name: "solution", value: "Upgrade to Open-Xchange (OX) AppSuite
  version 7.4.2-rev9 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/bugtraq/2014-03/0108.html" );
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
	if(IsMatchRegexp( oxVer, "^(7\\.4\\.2)" )){
		if(version_is_less( version: oxVer, test_version: "7.4.2.9" )){
			report = "Installed Version: " + oxVer + "\nFixed Version:     7.4.2-rev9 \n";
			security_message( port: oxPort, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

