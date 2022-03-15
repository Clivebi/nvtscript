CPE = "cpe:/a:squid-cache:squid";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807793" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2016-3947", "CVE-2016-3948" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-04-18 18:23:23 +0530 (Mon, 18 Apr 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Squid Multiple Denial of Service Vulnerabilities April16 (Windows)" );
	script_tag( name: "summary", value: "This host is running Squid and is prone
  to multiple denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A buffer overrun in the 'Icmp6::Recv' function in 'icmp/Icmp6.cc' script
    in the 'pinger' process.

  - An incorrect bounds checking while processing HTTP responses." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  HTTP servers to cause a denial of service, or write sensitive information to
  log files." );
	script_tag( name: "affected", value: "Squid version 3.x before 3.5.16 and 4.x
  before 4.0.8 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Squid version 3.5.16 or 4.0.8
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://access.redhat.com/security/cve/cve-2016-3948" );
	script_xref( name: "URL", value: "https://access.redhat.com/security/cve/cve-2016-3947" );
	script_xref( name: "URL", value: "http://www.squid-cache.org/Advisories/SQUID-2016_4.txt" );
	script_xref( name: "URL", value: "http://www.squid-cache.org/Advisories/SQUID-2016_3.txt" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_squid_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "squid_proxy_server/installed", "Host/runs_windows" );
	script_require_ports( "Services/www", 3128, 8080 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!squidPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!squidVer = get_app_version( cpe: CPE, port: squidPort )){
	exit( 0 );
}
if(IsMatchRegexp( squidVer, "^(3|4)" )){
	if( version_in_range( version: squidVer, test_version: "3.0.0", test_version2: "3.5.15" ) ){
		fix = "3.5.16";
		VULN = TRUE;
	}
	else {
		if(version_in_range( version: squidVer, test_version: "4.0.0", test_version2: "4.0.7" )){
			fix = "4.0.8";
			VULN = TRUE;
		}
	}
	if(VULN){
		report = report_fixed_ver( installed_version: squidVer, fixed_version: fix );
		security_message( data: report, port: squidPort );
		exit( 0 );
	}
}

