if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902610" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-07-22 12:16:19 +0200 (Fri, 22 Jul 2011)" );
	script_cve_id( "CVE-2010-3271" );
	script_bugtraq_id( 48305 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "IBM WebSphere Application Server Multiple CSRF Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_ibm_websphere_detect.sc" );
	script_mandatory_keys( "ibm_websphere_application_server/installed" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/44909" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/68069" );
	script_xref( name: "URL", value: "http://www.coresecurity.com/content/IBM-WebSphere-CSRF" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote users to gain sensitive
  information and conduct other malicious activities." );
	script_tag( name: "affected", value: "IBM WebSphere Application Server (WAS) 7.0.0.13 and prior." );
	script_tag( name: "insight", value: "The flaws are due to by improper validation of user-supplied
  input in the Global Security panel and master configuration save functionality.
  which allows attacker to force a logged-in administrator to perform unwanted actions." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "summary", value: "The host is running IBM WebSphere Application Server and is
  prone to cross-site request forgery vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
CPE = "cpe:/a:ibm:websphere_application_server";
if(!vers = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less_equal( version: vers, test_version: "7.0.0.13" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "7.0.0.14" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

