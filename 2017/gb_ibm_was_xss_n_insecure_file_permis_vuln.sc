CPE = "cpe:/a:ibm:websphere_application_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811254" );
	script_version( "2021-09-09T08:01:35+0000" );
	script_cve_id( "CVE-2017-1380", "CVE-2017-1382" );
	script_tag( name: "cvss_base", value: "3.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-09 08:01:35 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-07-25 12:01:55 +0530 (Tue, 25 Jul 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "IBM Websphere Application Server 'XSS' And 'Insecure File Permissions' Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with IBM Websphere
  application server and is prone to XSS and insecure file permissions
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Insecure file permissions after custom startup scripts are run. The custom
    startup script will not pull the umask from the server.xml.

  - Insufficient sanitizaion of input in the Web UI." );
	script_tag( name: "impact", value: "Successful exploitation will allow a local
  attacker could exploit this to gain access to files with an unknown impact and
  allow remote attacker to embed arbitrary JavaScript code in the Web UI thus
  altering the intended functionality potentially leading to credentials disclosure
  within a trusted session." );
	script_tag( name: "affected", value: "IBM WebSphere Application Server (WAS)
  V9.0.0.0 through 9.0.0.4, V8.5.0.0 through 8.5.5.11, V8.0.0.0 through 8.0.0.13
  and V7.0.0.0 through 7.0.0.43." );
	script_tag( name: "solution", value: "Upgrade to IBM WebSphere Application
  Server (WAS) 9.0.0.5 or 8.5.5.12 or 8.0.0.14 or 7.0.0.45 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg22004785" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg22004786" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_ibm_websphere_detect.sc" );
	script_mandatory_keys( "ibm_websphere_application_server/installed" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg22004785" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!wasVer = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(IsMatchRegexp( wasVer, "^[7-9]" )){
	if( IsMatchRegexp( wasVer, "^7\\.0\\.0" ) ){
		if(version_in_range( version: wasVer, test_version: "7.0.0.0", test_version2: "7.0.0.43" )){
			fix = "7.0.0.45";
		}
	}
	else {
		if( IsMatchRegexp( wasVer, "^8\\.0\\.0" ) ){
			if(version_in_range( version: wasVer, test_version: "8.0.0.0", test_version2: "8.0.0.12" )){
				fix = "8.0.0.13";
			}
		}
		else {
			if( IsMatchRegexp( wasVer, "^8\\.5\\.5" ) ){
				if(version_in_range( version: wasVer, test_version: "8.5.5.0", test_version2: "8.5.5.10" )){
					fix = "8.5.5.11";
				}
			}
			else {
				if(IsMatchRegexp( wasVer, "^9\\.0\\.0" )){
					if(version_in_range( version: wasVer, test_version: "9.0.0.0", test_version2: "9.0.0.1" )){
						fix = "9.0.0.2";
					}
				}
			}
		}
	}
	if(fix){
		report = report_fixed_ver( installed_version: wasVer, fixed_version: fix );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

