CPE = "cpe:/a:adobe:acrobat_reader_dc_continuous";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815529" );
	script_version( "2021-08-30T13:01:21+0000" );
	script_cve_id( "CVE-2019-7832", "CVE-2019-7965", "CVE-2019-8002", "CVE-2019-8003", "CVE-2019-8004", "CVE-2019-8005", "CVE-2019-8006", "CVE-2019-8007", "CVE-2019-8008", "CVE-2019-8009", "CVE-2019-8010", "CVE-2019-8011", "CVE-2019-8012", "CVE-2019-8013", "CVE-2019-8014", "CVE-2019-8015", "CVE-2019-8016", "CVE-2019-8017", "CVE-2019-8018", "CVE-2019-8019", "CVE-2019-8020", "CVE-2019-8021", "CVE-2019-8022", "CVE-2019-8023", "CVE-2019-8024", "CVE-2019-8025", "CVE-2019-8026", "CVE-2019-8027", "CVE-2019-8028", "CVE-2019-8029", "CVE-2019-8030", "CVE-2019-8031", "CVE-2019-8032", "CVE-2019-8033", "CVE-2019-8034", "CVE-2019-8035", "CVE-2019-8036", "CVE-2019-8037", "CVE-2019-8038", "CVE-2019-8039", "CVE-2019-8040", "CVE-2019-8041", "CVE-2019-8042", "CVE-2019-8043", "CVE-2019-8044", "CVE-2019-8045", "CVE-2019-8046", "CVE-2019-8047", "CVE-2019-8048", "CVE-2019-8049", "CVE-2019-8050", "CVE-2019-8051", "CVE-2019-8052", "CVE-2019-8053", "CVE-2019-8054", "CVE-2019-8055", "CVE-2019-8056", "CVE-2019-8057", "CVE-2019-8058", "CVE-2019-8059", "CVE-2019-8060", "CVE-2019-8061", "CVE-2019-8077", "CVE-2019-8094", "CVE-2019-8095", "CVE-2019-8096", "CVE-2019-8097", "CVE-2019-8098", "CVE-2019-8099", "CVE-2019-8100", "CVE-2019-8101", "CVE-2019-8102", "CVE-2019-8103", "CVE-2019-8104", "CVE-2019-8105", "CVE-2019-8106" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-30 13:01:21 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-08-14 15:14:48 +0530 (Wed, 14 Aug 2019)" );
	script_name( "Adobe Acrobat Reader DC (Continuous Track) Security Updates (apsb19-41) - Windows" );
	script_tag( name: "summary", value: "This host is installed with Adobe Acrobat
  Reader DC (Continuous Track) and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Out of bounds read error.

  - Out of bounds write error.

  - Command injection.

  - Use after free error.

  - Heap overflow error.

  - Buffer error.

  - Double free error.

  - Integer overflow error.

  - Internal IP disclosure error.

  - Type confusion

  - Untrusted pointer dereference error" );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker to execute arbitrary code and disclose sensitive information." );
	script_tag( name: "affected", value: "Adobe Acrobat Reader DC (Continuous Track)
  2019.012.20035 and earlier versions on Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Acrobat Reader DC Continuous
  version 2019.012.20036 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/acrobat/apsb19-41.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_acrobat_reader_dc_cont_detect_win.sc" );
	script_mandatory_keys( "Adobe/Acrobat/ReaderDC/Continuous/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "19.012.20036" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "19.012.20036 (2019.012.20036)", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

