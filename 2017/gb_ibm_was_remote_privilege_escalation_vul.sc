CPE = "cpe:/a:ibm:websphere_application_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811442" );
	script_version( "2021-09-16T14:01:49+0000" );
	script_cve_id( "CVE-2017-1151" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-16 14:01:49 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-08-04 11:32:43 +0530 (Fri, 04 Aug 2017)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "IBM Websphere Application Server Remote Privilege Escalation Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with IBM Websphere
  application server and is prone to remote privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to a potential privilege
  escalation vulnerability in WebSphere Application Server traditional when using
  the OpenID Connect (OIDC) Trust Association Interceptor (TAI)." );
	script_tag( name: "impact", value: "Successful exploitation will allow a user to
  gain elevated privileges on the system." );
	script_tag( name: "affected", value: "IBM WebSphere Application Server (WAS)
  V9.0.0.0 through 9.0.0.3, V8.5.5.3 through 8.5.5.11, V8.0.0.10 through 8.0.0.13" );
	script_tag( name: "solution", value: "Upgrade to IBM WebSphere Application
  Server (WAS) 9.0.0.4 or 8.5.5.12 or 8.0.0.14 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21999293" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
if(IsMatchRegexp( wasVer, "^[89]" )){
	if( IsMatchRegexp( wasVer, "^8\\.0\\.0\\.1" ) ){
		if(version_in_range( version: wasVer, test_version: "8.0.0.10", test_version2: "8.0.0.13" )){
			fix = "8.0.0.14";
		}
	}
	else {
		if( IsMatchRegexp( wasVer, "^8\\.5\\.5" ) ){
			if(version_in_range( version: wasVer, test_version: "8.5.5.3", test_version2: "8.5.5.11" )){
				fix = "8.5.5.12";
			}
		}
		else {
			if(IsMatchRegexp( wasVer, "^9\\.0\\.0" )){
				if(version_in_range( version: wasVer, test_version: "9.0.0.0", test_version2: "9.0.0.3" )){
					fix = "9.0.0.4";
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

