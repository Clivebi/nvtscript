CPE = "cpe:/h:ibm:websphere_datapower_xc10_appliance";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808184" );
	script_version( "2019-04-26T09:28:56+0000" );
	script_cve_id( "CVE-2016-2870" );
	script_bugtraq_id( 91551 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2019-04-26 09:28:56 +0000 (Fri, 26 Apr 2019)" );
	script_tag( name: "creation_date", value: "2016-07-05 14:46:07 +0530 (Tue, 05 Jul 2016)" );
	script_name( "IBM Websphere DataPower XC10 Denial of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_ibm_websphere_datapower_xc10_detect.sc" );
	script_mandatory_keys( "IBM/Websphere/Datapower/XC10/Version" );
	script_require_ports( "Services/www", 80, 443 );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21983035" );
	script_tag( name: "summary", value: "This host is installed with IBM Websphere
  datapower XC10 and is prone to denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to a buffer
  overflow in the Command Line Interface (CLI)." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to cause a denial of service." );
	script_tag( name: "affected", value: "IBM WebSphere DataPower XC10
  appliances 2.1 and 2.5." );
	script_tag( name: "solution", value: "Apply the Fix pack from the referenced vendor link." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!xc_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!xc_Ver = get_app_version( cpe: CPE, port: xc_port )){
	exit( 0 );
}
if(version_is_equal( version: xc_Ver, test_version: "2.1" ) || version_is_equal( version: xc_Ver, test_version: "2.5" )){
	report = report_fixed_ver( installed_version: xc_Ver, fixed_version: "Apply fixpack IT15175" );
	security_message( data: report, port: xc_port );
	exit( 0 );
}
exit( 99 );

