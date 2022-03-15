CPE = "cpe:/a:apple:safari";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802233" );
	script_version( "2020-03-02T13:53:38+0000" );
	script_tag( name: "last_modification", value: "2020-03-02 13:53:38 +0000 (Mon, 02 Mar 2020)" );
	script_tag( name: "creation_date", value: "2011-08-12 14:44:50 +0200 (Fri, 12 Aug 2011)" );
	script_cve_id( "CVE-2010-1383", "CVE-2010-1420", "CVE-2011-0214", "CVE-2011-0215", "CVE-2011-0216", "CVE-2011-0217", "CVE-2011-0218", "CVE-2011-0219", "CVE-2011-0221", "CVE-2011-0222", "CVE-2011-0223", "CVE-2011-0225", "CVE-2011-0232", "CVE-2011-0233", "CVE-2011-0234", "CVE-2011-0235", "CVE-2011-0237", "CVE-2011-0238", "CVE-2011-0240", "CVE-2011-0241", "CVE-2011-0242", "CVE-2011-0244", "CVE-2011-0253", "CVE-2011-0254", "CVE-2011-0255", "CVE-2011-1288", "CVE-2011-1453", "CVE-2011-1457", "CVE-2011-1462", "CVE-2011-1774", "CVE-2011-1797", "CVE-2011-3443" );
	script_bugtraq_id( 48820, 48823, 48825, 48827, 48828, 48831, 48832, 48833, 48837, 48839, 48840, 48841, 48842, 48843, 48844, 48845, 48846, 48847, 48848, 48849, 48850, 48851, 48852, 48853, 48854, 48855, 48856, 48857, 48858, 48859, 51035 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Apple Safari Multiple Vulnerabilities - July 2011 (Mac OS X)" );
	script_xref( name: "URL", value: "http://support.apple.com/kb/HT4808" );
	script_xref( name: "URL", value: "http://lists.apple.com/archives/security-announce/2011/Jul/msg00002.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "macosx_safari_detect.sc" );
	script_mandatory_keys( "AppleSafari/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation may result in information disclosure, remote code
  execution, denial of service, or other consequences." );
	script_tag( name: "affected", value: "Apple Safari versions prior to 5.0.6/5.1." );
	script_tag( name: "insight", value: "Please see the references for more details about the vulnerabilities." );
	script_tag( name: "solution", value: "Upgrade to Apple Safari version 5.0.6/5.1 or later." );
	script_tag( name: "summary", value: "The host is installed with Apple Safari web browser and is prone
  to multiple vulnerabilities." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "5.0.6" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.0.6", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

