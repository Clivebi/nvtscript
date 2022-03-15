CPE = "cpe:/a:adobe:acrobat_reader";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814851" );
	script_version( "2021-08-30T14:01:20+0000" );
	script_cve_id( "CVE-2018-19725", "CVE-2019-7018", "CVE-2019-7019", "CVE-2019-7020", "CVE-2019-7021", "CVE-2019-7022", "CVE-2019-7023", "CVE-2019-7024", "CVE-2019-7025", "CVE-2019-7026", "CVE-2019-7027", "CVE-2019-7028", "CVE-2019-7029", "CVE-2019-7030", "CVE-2019-7031", "CVE-2019-7032", "CVE-2019-7033", "CVE-2019-7034", "CVE-2019-7035", "CVE-2019-7036", "CVE-2019-7037", "CVE-2019-7038", "CVE-2019-7039", "CVE-2019-7040", "CVE-2019-7041", "CVE-2019-7042", "CVE-2019-7043", "CVE-2019-7044", "CVE-2019-7045", "CVE-2019-7046", "CVE-2019-7047", "CVE-2019-7048", "CVE-2019-7049", "CVE-2019-7050", "CVE-2019-7051", "CVE-2019-7052", "CVE-2019-7053", "CVE-2019-7054", "CVE-2019-7055", "CVE-2019-7056", "CVE-2019-7057", "CVE-2019-7058", "CVE-2019-7059", "CVE-2019-7060", "CVE-2019-7062", "CVE-2019-7063", "CVE-2019-7064", "CVE-2019-7065", "CVE-2019-7066", "CVE-2019-7067", "CVE-2019-7068", "CVE-2019-7069", "CVE-2019-7070", "CVE-2019-7071", "CVE-2019-7072", "CVE-2019-7073", "CVE-2019-7074", "CVE-2019-7075", "CVE-2019-7076", "CVE-2019-7077", "CVE-2019-7078", "CVE-2019-7079", "CVE-2019-7080", "CVE-2019-7081", "CVE-2019-7082", "CVE-2019-7083", "CVE-2019-7084", "CVE-2019-7085", "CVE-2019-7086", "CVE-2019-7087", "CVE-2019-7089" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-30 14:01:20 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-10 20:15:00 +0000 (Thu, 10 Oct 2019)" );
	script_tag( name: "creation_date", value: "2019-02-14 11:32:21 +0530 (Thu, 14 Feb 2019)" );
	script_name( "Adobe Acrobat Reader 2017 Multiple Vulnerabilities-apsb19-07 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Acrobat Reader
  2017 and is prone to multiple arbitrary code execution vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Multiple buffer errors.

  - A data leakage error.

  - An integer overflow error.

  - Multiple out-of-bounds read errors.

  - Multiple security bypass errors.

  - Multiple out-of-bounds write errors.

  - Multiple type confusion errors.

  - Multiple untrusted pointer dereference errors.

  - Multiple use after free errors." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker to execute arbitrary code in the context of the current user,
  escalate privileges and gain access to sensitive information." );
	script_tag( name: "affected", value: "Adobe Acrobat Reader 2017.011.30113 and earlier
  versions on Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Acrobat Reader 2017 version
  2017.011.30120 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/acrobat/apsb19-07.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_prdts_detect_win.sc" );
	script_mandatory_keys( "Adobe/Reader/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "17.0", test_version2: "17.011.30113" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "17.011.30120 (2017.011.30120)", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

