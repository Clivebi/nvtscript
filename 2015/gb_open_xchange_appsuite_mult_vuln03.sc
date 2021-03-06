CPE = "cpe:/a:open-xchange:open-xchange_appsuite";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806522" );
	script_version( "2019-07-05T10:16:38+0000" );
	script_cve_id( "CVE-2013-5200", "CVE-2013-5935", "CVE-2013-5936", "CVE-2013-5934" );
	script_bugtraq_id( 62311 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2019-07-05 10:16:38 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2015-11-02 10:34:36 +0530 (Mon, 02 Nov 2015)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Open-Xchange (OX) AppSuite Multiple Vulnerabilities -03 Nov15" );
	script_tag( name: "summary", value: "This host is installed with
  Open-Xchange (OX) AppSuite and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to error in
  the Hazelcast based cluster API implementation at the Open-Xchange backend." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to bypass access restriction and to obtain sensitive information." );
	script_tag( name: "affected", value: "Open-Xchange (OX) AppSuite versions
  7.0.x before 7.0.2-rev15 and 7.2.x before 7.2.2-rev16" );
	script_tag( name: "solution", value: "Upgrade to Open-Xchange (OX) AppSuite
  version 7.0.2-rev15 or 7.2.2-rev16 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/bugtraq/2013-09/0032.html" );
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
	if(version_in_range( version: oxVer, test_version: "7.0", test_version2: "7.0.2.14" )){
		fix = "7.0.2-rev15";
		VULN = TRUE;
	}
	if(version_in_range( version: oxVer, test_version: "7.2", test_version2: "7.2.2.15" )){
		fix = "7.2.2-rev16";
		VULN = TRUE;
	}
	if(VULN){
		report = "Installed Version: " + oxVer + "\nFixed Version:     " + fix + "\n";
		security_message( port: oxPort, data: report );
		exit( 0 );
	}
}
exit( 99 );

