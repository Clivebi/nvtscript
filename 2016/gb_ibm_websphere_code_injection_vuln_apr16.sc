CPE = "cpe:/a:ibm:websphere_application_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807675" );
	script_version( "2021-09-17T13:01:55+0000" );
	script_cve_id( "CVE-2016-0283" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-17 13:01:55 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-12-03 03:16:00 +0000 (Sat, 03 Dec 2016)" );
	script_tag( name: "creation_date", value: "2016-04-21 12:11:03 +0530 (Thu, 21 Apr 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "IBM WebSphere Application Server Code Injection Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with IBM Websphere
  application server and is prone to code injection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an improper validation
  of user-supplied input in the OpenID Connect (OIDC) client web application." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML via a crafted URL." );
	script_tag( name: "affected", value: "IBM WebSphere Application Server (WAS)
  Liberty Profile 8.5.x before 8.5.5.9" );
	script_tag( name: "solution", value: "Upgrade to IBM WebSphere Application
  Server (WAS) Liberty Profile version 8.5.5.9, or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21978293" );
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
if(version_in_range( version: wasVer, test_version: "8.5", test_version2: "8.5.5.8" )){
	report = report_fixed_ver( installed_version: wasVer, fixed_version: "8.5.5.9" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

