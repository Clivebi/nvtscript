CPE = "cpe:/a:adobe:acrobat_reader";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800428" );
	script_version( "2020-04-23T12:22:09+0000" );
	script_cve_id( "CVE-2009-3953", "CVE-2009-3954", "CVE-2009-3955", "CVE-2009-3956", "CVE-2009-3957", "CVE-2009-3958", "CVE-2009-3959", "CVE-2009-4324" );
	script_bugtraq_id( 37758, 37761, 37757, 37763, 37760, 37759, 37756 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-23 12:22:09 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2010-01-16 12:13:24 +0100 (Sat, 16 Jan 2010)" );
	script_name( "Adobe Reader Multiple Vulnerabilities -jan10 (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Reader and is prone to multiple
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Please see the references for more information." );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker cause memory corruption or
  denial of service." );
	script_tag( name: "affected", value: "Adobe Reader and Acrobat 9.x before 9.3 on Linux." );
	script_tag( name: "solution", value: "Update to Adobe Reader 9.3 or later." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb10-02.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_prdts_detect_lin.sc" );
	script_mandatory_keys( "Adobe/Reader/Linux/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!readerVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( readerVer, "^9\\." )){
	if(version_in_range( version: readerVer, test_version: "9.0", test_version2: "9.2" )){
		report = report_fixed_ver( installed_version: readerVer, vulnerable_range: "9.0 - 9.2" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}

