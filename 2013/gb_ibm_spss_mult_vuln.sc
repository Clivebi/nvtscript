CPE = "cpe:/a:ibm:spss_samplepower";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803398" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2012-5947", "CVE-2012-5946", "CVE-2012-5945", "CVE-2013-0593" );
	script_bugtraq_id( 59556, 59559, 59557, 59527 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-05-08 11:50:37 +0530 (Wed, 08 May 2013)" );
	script_name( "IBM SPSS SamplePower Multiple Vulnerabilities (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/53234" );
	script_xref( name: "URL", value: "http://www.ibm.com/support/docview.wss?uid=swg21635476" );
	script_xref( name: "URL", value: "http://www.ibm.com/support/docview.wss?uid=swg21635515" );
	script_xref( name: "URL", value: "http://www.ibm.com/support/docview.wss?uid=swg21635511" );
	script_xref( name: "URL", value: "http://www.ibm.com/support/docview.wss?uid=swg21635503" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_ibm_spss_sample_power_detect_win.sc" );
	script_mandatory_keys( "IBM/SPSS/Win/Installed" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to execute arbitrary
  code in the context of the application using the ActiveX control. Failed
  attempts will likely result in denial of service conditions." );
	script_tag( name: "affected", value: "IBM SPSS SamplePower version 3.0 and prior" );
	script_tag( name: "insight", value: "Multiple flaws due to:

  - Unspecified error in the vsflex7l ActiveX control.

  - Unspecified flaw in the olch2x32 ActiveX control.

  - Error when handling the 'ComboList' or 'ColComboList' in Vsflex8l
    ActiveX control.

  - Error when handling the 'TabCaption' buffer in c1sizer ActiveX control." );
	script_tag( name: "solution", value: "Upgrade to IBM SPSS SamplePower version 3.0 FP1 (3.0.0.1) or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is installed with IBM SPSS SamplePower and is prone
  to multiple vulnerabilities." );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less_equal( version: vers, test_version: "3.0.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.0 FP1 (3.0.0.1)", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

