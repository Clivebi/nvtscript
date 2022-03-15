CPE = "cpe:/a:oracle:iplanet_web_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801607" );
	script_version( "2021-05-12T14:22:53+0000" );
	script_tag( name: "last_modification", value: "2021-05-12 14:22:53 +0000 (Wed, 12 May 2021)" );
	script_tag( name: "creation_date", value: "2010-10-22 15:51:55 +0200 (Fri, 22 Oct 2010)" );
	script_bugtraq_id( 43984 );
	script_cve_id( "CVE-2010-3544", "CVE-2010-3545", "CVE-2010-3514", "CVE-2010-3512" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_name( "Oracle iPlanet Web Server Multiple Unspecified Vulnerabilities (cpuoct2010)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_sun_oracle_web_server_http_detect.sc" );
	script_mandatory_keys( "oracle/iplanet_web_server/detected" );
	script_xref( name: "URL", value: "https://www.oracle.com/security-alerts/cpuoct2010.html#AppendixSUNS" );
	script_xref( name: "Advisory-ID", value: "cpuoct2010" );
	script_tag( name: "summary", value: "Oracle iPlanet Web Server is prone to multiple unspecified
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaws are due to unspecified errors, which allow remote
  attackers to affect confidentiality, integrity and availability via unknown vectors related to
  Administration." );
	script_tag( name: "impact", value: "Successful exploitation may allow remote attackers to affect
  confidentiality, integrity and availability via unknown vectors related to Administration." );
	script_tag( name: "affected", value: "Oracle iPlanet Web Server (Sun Java System Web Server) 7.0." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for
  more information." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less_equal( version: vers, test_version: "7.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "Apply the patch." );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

