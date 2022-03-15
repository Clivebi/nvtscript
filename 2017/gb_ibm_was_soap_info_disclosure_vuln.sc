CPE = "cpe:/a:ibm:websphere_application_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811129" );
	script_version( "2021-09-13T11:01:38+0000" );
	script_cve_id( "CVE-2016-9736" );
	script_bugtraq_id( 96076 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-13 11:01:38 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-06-13 16:53:00 +0000 (Tue, 13 Jun 2017)" );
	script_tag( name: "creation_date", value: "2017-06-21 16:24:33 +0530 (Wed, 21 Jun 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "IBM Websphere Application Server 'SOAP Requests' Information Disclosure Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with IBM Websphere
  application server and is prone to information discloure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to usage of malformed SOAP
  requests." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to obtain sensitive information that may lead to further attacks." );
	script_tag( name: "affected", value: "IBM WebSphere Application Server (WAS)
   V9.0.0.0 through 9.0.0.1, V8.5.0.0 through 8.5.5.10, V8.0.0.0 through 8.0.0.12." );
	script_tag( name: "solution", value: "Upgrade to IBM WebSphere Application
  Server (WAS) 9.0.0.2, or 8.5.5.11, or 8.0.0.13, or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www-01.ibm.com/support/docview.wss?uid=swg21991469" );
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
exit( 99 );

