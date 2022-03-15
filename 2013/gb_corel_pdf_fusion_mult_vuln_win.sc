CPE = "cpe:/a:corel:pdf_fusion";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804109" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2013-0742", "CVE-2013-3248" );
	script_bugtraq_id( 61160, 61010 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-10-15 14:34:30 +0530 (Tue, 15 Oct 2013)" );
	script_name( "Corel PDF Fusion Multiple Vulnerabilities (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Corel PDF Fusion and is prone to multiple
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - The application loads a library (wintab32.dll) in an insecure manner. This
  can be exploited to load arbitrary libraries by tricking a user into opening
  a '.pdf' or '.xps' file.

  - A boundary error exists when parsing names in ZIP directory entries of a XPS
  file and can be exploited to cause a stack-based buffer overflow by tricking
  a user into opening a specially crafted XPS file." );
	script_tag( name: "affected", value: "Corel PDF Fusion 1.11" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attacker to execute arbitrary code,
  cause a denial of service (application crash) and allows local users to gain
  privileges via a Trojan horse wintab32.dll file." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/52707/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/61010" );
	script_xref( name: "URL", value: "http://cxsecurity.com/cveshow/CVE-2013-0742" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_corel_pdf_fusion_detect_win.sc" );
	script_mandatory_keys( "Corel/PDF/Fusion/Win/Ver" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!pdfVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_equal( version: pdfVer, test_version: "1.11.0000" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}

