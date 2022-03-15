CPE = "cpe:/a:ibm:websphere_application_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806889" );
	script_version( "2020-10-23T13:29:00+0000" );
	script_cve_id( "CVE-2014-6166", "CVE-2014-6164" );
	script_bugtraq_id( 71836, 71837 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-03-03 18:23:41 +0530 (Thu, 03 Mar 2016)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "IBM Websphere Application Server Multiple Vulnerabilities-03 Mar16" );
	script_tag( name: "summary", value: "This host is installed with IBM Websphere
  application server and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An XML External Entity Injection (XXE) error when processing XML data.

  - A vulnerability in handling cookies." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to spoof OpenID and OpenID connect cookies, to execute script in a
  victim's Web browser within the security context of the hosting Web site,
  once the URL is clicked." );
	script_tag( name: "affected", value: "IBM WebSphere Application Server (WAS)
  8.0.x before 8.0.0.10 and 8.5.x before 8.5.5.4" );
	script_tag( name: "solution", value: "Upgrade to IBM WebSphere Application
  Server (WAS) version 8.0.0.10, or 8.5.5.4, or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_ibm_websphere_detect.sc" );
	script_mandatory_keys( "ibm_websphere_application_server/installed" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21690185" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21671835" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!wasVer = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if( version_in_range( version: wasVer, test_version: "8.0", test_version2: "8.0.0.9" ) ){
	fix = "8.0.0.10";
	VULN = TRUE;
}
else {
	if(version_in_range( version: wasVer, test_version: "8.5", test_version2: "8.5.5.3" )){
		fix = "8.5.5.4";
		VULN = TRUE;
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: wasVer, fixed_version: fix );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

