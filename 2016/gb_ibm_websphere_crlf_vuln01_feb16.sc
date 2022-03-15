CPE = "cpe:/a:ibm:websphere_application_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806883" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2015-2017" );
	script_bugtraq_id( 78457 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-03-01 14:45:31 +0530 (Tue, 01 Mar 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "IBM Websphere Application Server CRLF Injection Vulnerability Feb16" );
	script_tag( name: "summary", value: "This host is installed with IBM Websphere
  application server and is prone to CRLF injection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an
  HTTP response splitting attack vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to use specially-crafted URL to cause the server to return a split
  response, once the URL is clicked. This would allow the attacker to perform
  further attacks, such as Web cache poisoning, cross-site scripting, and
  possibly obtain sensitive information." );
	script_tag( name: "affected", value: "IBM WebSphere Application Server (WAS)
  6.1 through 6.1.0.47, 7.0 before 7.0.0.39, 8.0 before 8.0.0.12,
  and 8.5 before 8.5.5.8." );
	script_tag( name: "solution", value: "Upgrade to IBM WebSphere Application
  Server (WAS) 6.1.0.48, or 7.0.0.39, or 8.0.0.12, or 8.5.5.8" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21966837" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_ibm_websphere_detect.sc" );
	script_mandatory_keys( "ibm_websphere_application_server/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!wasVer = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if( version_in_range( version: wasVer, test_version: "6.1", test_version2: "6.1.0.47" ) ){
	fix = "6.1.0.48";
	VULN = TRUE;
}
else {
	if( version_in_range( version: wasVer, test_version: "7.0", test_version2: "7.0.0.38" ) ){
		fix = "7.0.0.39";
		VULN = TRUE;
	}
	else {
		if( version_in_range( version: wasVer, test_version: "8.0", test_version2: "8.0.0.11" ) ){
			fix = "8.0.0.12";
			VULN = TRUE;
		}
		else {
			if(version_in_range( version: wasVer, test_version: "8.5", test_version2: "8.5.5.7" )){
				fix = "8.5.5.8";
				VULN = TRUE;
			}
		}
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: wasVer, fixed_version: fix );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

