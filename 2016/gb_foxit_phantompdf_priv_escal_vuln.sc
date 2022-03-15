CPE = "cpe:/a:foxitsoftware:phantompdf";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807561" );
	script_version( "2019-07-05T10:16:38+0000" );
	script_cve_id( "CVE-2015-8843" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-07-05 10:16:38 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2016-04-25 16:44:43 +0530 (Mon, 25 Apr 2016)" );
	script_name( "Foxit PhantomPDF Local Privilege Escalation Vulnerability" );
	script_tag( name: "summary", value: "The host is installed with Foxit PhantomPDF
  and is prone to privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an error in
  FoxitCloudUpdateService service which can trigger a memory corruption condition
  by writing certain data to a shared memory region." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to execute code under the context of system." );
	script_tag( name: "affected", value: "Foxit PhantomPDF version 7.2.0.722
  and earlier." );
	script_tag( name: "solution", value: "Upgrade to Foxit PhantomPDF version
  7.2.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://www.zerodayinitiative.com/advisories/ZDI-15-640" );
	script_xref( name: "URL", value: "https://www.foxitsoftware.com/support/security-bulletins.php" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_foxit_phantom_reader_detect.sc" );
	script_mandatory_keys( "foxit/phantompdf/ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!foxitVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less_equal( version: foxitVer, test_version: "7.2.0.722" )){
	report = report_fixed_ver( installed_version: foxitVer, fixed_version: "7.2.2.929" );
	security_message( data: report );
	exit( 0 );
}

