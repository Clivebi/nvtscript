CPE = "cpe:/a:squid-cache:squid";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808038" );
	script_version( "2020-03-04T09:29:37+0000" );
	script_cve_id( "CVE-2016-4555", "CVE-2016-4556" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-03-04 09:29:37 +0000 (Wed, 04 Mar 2020)" );
	script_tag( name: "creation_date", value: "2016-05-18 10:22:38 +0530 (Wed, 18 May 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Squid Multiple Denial of Service Vulnerabilities-01 May16 (Windows)" );
	script_tag( name: "summary", value: "This host is running Squid and is prone
  to multiple denial of service vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to an incorrect
  pointer handling and reference counting when processing ESI responses." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause a denial of service." );
	script_tag( name: "affected", value: "Squid version 3.x before 3.5.18 and 4.x
  before 4.0.10 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Squid version 3.5.18 or 4.0.10
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.squid-cache.org/Advisories/SQUID-2016_9.txt" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
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
if(IsMatchRegexp( squidVer, "^(3|4)\\." )){
	if( version_in_range( version: squidVer, test_version: "3.0.0", test_version2: "3.5.17" ) ){
		fix = "3.5.18";
		VULN = TRUE;
	}
	else {
		if(version_in_range( version: squidVer, test_version: "4.0.0", test_version2: "4.0.9" )){
			fix = "4.0.10";
			VULN = TRUE;
		}
	}
	if(VULN){
		report = report_fixed_ver( installed_version: squidVer, fixed_version: fix );
		security_message( data: report, port: squidPort );
		exit( 0 );
	}
}

