CPE = "cpe:/a:foxitsoftware:reader";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805364" );
	script_version( "$Revision: 11872 $" );
	script_cve_id( "CVE-2015-2789" );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-04-07 18:04:50 +0530 (Tue, 07 Apr 2015)" );
	script_name( "Foxit Reader Cloud Plugin Windows Search Path Vulnerability" );
	script_tag( name: "summary", value: "The host is installed with Foxit Reader
  Cloud Plugin and is prone to windows search path Vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to SYSTEMDRIVE folder,
  local users can gain privileges via a Trojan horse." );
	script_tag( name: "impact", value: "Successful exploitation will allow local
  attackers to gain privileges and execute malicious files." );
	script_tag( name: "affected", value: "Foxit Reader version 6.1 before version
  7.0.6.1126" );
	script_tag( name: "solution", value: "Upgrade to Foxit Reader version
  7.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1031879" );
	script_xref( name: "URL", value: "http://www.foxitsoftware.com/support/security_bulletins.php#FRD-25" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
if(version_in_range( version: foxitVer, test_version: "6.1", test_version2: "7.0.6.1126" )){
	report = "Installed version: " + foxitVer + "\n" + "Fixed version:     7.1" + "\n";
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

