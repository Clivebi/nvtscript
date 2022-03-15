CPE = "cpe:/a:adobe:bridge_cc";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806871" );
	script_version( "2020-10-23T13:29:00+0000" );
	script_cve_id( "CVE-2016-0951", "CVE-2016-0952", "CVE-2016-0953" );
	script_bugtraq_id( 83114 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-02-15 13:37:52 +0530 (Mon, 15 Feb 2016)" );
	script_name( "Adobe Bridge CC Multiple Vulnerabilities Feb16" );
	script_tag( name: "summary", value: "The host is installed with Adobe Bridge
  CC and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to memory
  corruption vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code or cause a denial of service (memory
  corruption) via unspecified vectors." );
	script_tag( name: "affected", value: "Adobe Bridge CC before version 6.2 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Bridge CC 6.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/photoshop/apsb16-03.html" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_adobe_bridge_cc_detect.sc" );
	script_mandatory_keys( "Adobe/Bridge/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!prodVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: prodVer, test_version: "6.2" )){
	report = report_fixed_ver( installed_version: prodVer, fixed_version: "6.2" );
	security_message( data: report );
	exit( 0 );
}

