CPE = "cpe:/a:open-xchange:open-xchange_appsuite";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806082" );
	script_version( "$Revision: 11975 $" );
	script_cve_id( "CVE-2014-2077" );
	script_bugtraq_id( 71888 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-19 08:54:12 +0200 (Fri, 19 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-10-13 09:25:09 +0530 (Tue, 13 Oct 2015)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Open-Xchange AppSuite Email Subject Cross Site Scripting Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with OpenX and
  is prone to Cross Site Scripting Vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to email subject is not
  properly sanitized." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML." );
	script_tag( name: "affected", value: "Open-Xchange (OX) AppSuite version 7.4.1
  before 7.4.1-rev10, 7.4.2 before 7.4.2-rev8" );
	script_tag( name: "solution", value: "Upgrade to Open-Xchange (OX) AppSuite
  version 7.4.2-rev8 or 7.4.1-rev10 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/bugtraq/2014-03/0108.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_ox_app_suite_detect.sc" );
	script_mandatory_keys( "open_xchange_appsuite/installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "http://openx.com" );
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
	if(IsMatchRegexp( oxVer, "^(7\\.4\\.1)" )){
		if(version_is_less( version: oxVer, test_version: "7.4.2.10" )){
			fix = "7.4.1-rev10";
			VULN = TRUE;
		}
	}
	if(IsMatchRegexp( oxVer, "^(7\\.4\\.2)" )){
		if(version_is_less( version: oxVer, test_version: "7.4.2.8" )){
			fix = "7.4.2-rev8";
			VULN = TRUE;
		}
	}
	if(VULN){
		report = "Installed Version: " + oxVer + "\nFixed Version: " + fix + "\n";
		security_message( port: oxPort, data: report );
		exit( 0 );
	}
}
exit( 99 );

