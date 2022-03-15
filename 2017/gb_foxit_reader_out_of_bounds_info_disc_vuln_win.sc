CPE = "cpe:/a:foxitsoftware:reader";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807395" );
	script_version( "2021-09-13T11:01:38+0000" );
	script_cve_id( "CVE-2016-8334" );
	script_bugtraq_id( 93799 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-13 11:01:38 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-01-11 02:59:00 +0000 (Wed, 11 Jan 2017)" );
	script_tag( name: "creation_date", value: "2017-01-17 16:07:07 +0530 (Tue, 17 Jan 2017)" );
	script_name( "Foxit Reader Out of Bounds Read Local Information Disclosure Vulnerability (Windows)" );
	script_tag( name: "summary", value: "The host is installed with Foxit Reader
  and is prone to information disclosure vulnerability" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A large out of bounds read on the heap
  vulnerability in Foxit PDF Reader can potentially be abused for information
  disclosure. Combined with another vulnerability, it can be used to leak heap
  memory layout and in bypassing ASLR." );
	script_tag( name: "impact", value: "Successful exploitation will allow local
  attackers to obtain sensitive information that may aid in launching further
  attacks." );
	script_tag( name: "affected", value: "Foxit Reader version 8.0.2.805 on Windows" );
	script_tag( name: "solution", value: "Upgrade to Foxit Reader 8.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://vuldb.com/?id.95088" );
	script_xref( name: "URL", value: "http://www.talosintelligence.com/reports/TALOS-2016-0201" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_foxit_reader_detect_portable_win.sc" );
	script_mandatory_keys( "foxit/reader/ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!foxitVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(foxitVer == "8.0.2.805"){
	report = report_fixed_ver( installed_version: foxitVer, fixed_version: "8.1" );
	security_message( data: report );
	exit( 0 );
}

