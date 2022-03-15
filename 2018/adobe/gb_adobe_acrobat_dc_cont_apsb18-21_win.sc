CPE = "cpe:/a:adobe:acrobat_dc_continuous";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813665" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2018-12782", "CVE-2018-5015", "CVE-2018-5028", "CVE-2018-5032", "CVE-2018-5036", "CVE-2018-5038", "CVE-2018-5040", "CVE-2018-5041", "CVE-2018-5045", "CVE-2018-5052", "CVE-2018-5058", "CVE-2018-5067", "CVE-2018-12785", "CVE-2018-12788", "CVE-2018-12798", "CVE-2018-5009", "CVE-2018-5011", "CVE-2018-5065", "CVE-2018-12756", "CVE-2018-12770", "CVE-2018-12772", "CVE-2018-12773", "CVE-2018-12776", "CVE-2018-12783", "CVE-2018-12791", "CVE-2018-12792", "CVE-2018-12796", "CVE-2018-12797", "CVE-2018-5020", "CVE-2018-5021", "CVE-2018-5042", "CVE-2018-5059", "CVE-2018-5064", "CVE-2018-5069", "CVE-2018-5070", "CVE-2018-12754", "CVE-2018-12755", "CVE-2018-12758", "CVE-2018-12760", "CVE-2018-12771", "CVE-2018-12787", "CVE-2018-12802", "CVE-2018-5010", "CVE-2018-12803", "CVE-2018-5014", "CVE-2018-5016", "CVE-2018-5017", "CVE-2018-5018", "CVE-2018-5019", "CVE-2018-5022", "CVE-2018-5023", "CVE-2018-5024", "CVE-2018-5025", "CVE-2018-5026", "CVE-2018-5027", "CVE-2018-5029", "CVE-2018-5031", "CVE-2018-5033", "CVE-2018-5035", "CVE-2018-5039", "CVE-2018-5044", "CVE-2018-5046", "CVE-2018-5047", "CVE-2018-5048", "CVE-2018-5049", "CVE-2018-5050", "CVE-2018-5051", "CVE-2018-5053", "CVE-2018-5054", "CVE-2018-5055", "CVE-2018-5056", "CVE-2018-5060", "CVE-2018-5061", "CVE-2018-5062", "CVE-2018-5063", "CVE-2018-5066", "CVE-2018-5068", "CVE-2018-12757", "CVE-2018-12761", "CVE-2018-12762", "CVE-2018-12763", "CVE-2018-12764", "CVE-2018-12765", "CVE-2018-12766", "CVE-2018-12767", "CVE-2018-12768", "CVE-2018-12774", "CVE-2018-12777", "CVE-2018-12779", "CVE-2018-12780", "CVE-2018-12781", "CVE-2018-12786", "CVE-2018-12789", "CVE-2018-12790", "CVE-2018-12795", "CVE-2018-5057", "CVE-2018-12793", "CVE-2018-12794", "CVE-2018-5012", "CVE-2018-5030", "CVE-2018-5034", "CVE-2018-5037", "CVE-2018-5043", "CVE-2018-12784" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-21 16:20:00 +0000 (Wed, 21 Aug 2019)" );
	script_tag( name: "creation_date", value: "2018-07-12 13:11:59 +0530 (Thu, 12 Jul 2018)" );
	script_name( "Adobe Acrobat DC (Continuous Track) Multiple Vulnerabilities (apsb18-21) - Windows" );
	script_tag( name: "summary", value: "This host is installed with Adobe Acrobat DC
  (Continuous Track) and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A double free error.

  - Multiple heap overflow errors.

  - Multiple use-after-free errors.

  - Multiple out-of-bounds write errors.

  - A security bypass error.

  - Multiple out-of-bounds read errors.

  - Multiple type confusion errors.

  - An untrusted pointer dereference error.

  - MUltiple buffer errors." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker to gain escalated privileges, disclose sensitive information,
  execute arbitrary code on affected system and take control of the affected
  system." );
	script_tag( name: "affected", value: "Adobe Acrobat DC (Continuous Track) 2018.011.20040
  and earlier versions on Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Acrobat DC Continuous
  version 2018.011.20055 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/acrobat/apsb18-21.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_acrobat_dc_cont_detect_win.sc" );
	script_mandatory_keys( "Adobe/AcrobatDC/Continuous/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "18.011.20055" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "18.011.20055 (2018.011.20055)", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

