CPE = "cpe:/a:kde:konqueror";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900903" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-07-31 07:37:13 +0200 (Fri, 31 Jul 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-2537" );
	script_name( "KDE Konqueror Select Object Denial of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_kde_konqueror_detect.sc" );
	script_mandatory_keys( "KDE/Konqueror/Ver" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/9160" );
	script_xref( name: "URL", value: "http://www.g-sec.lu/one-bug-to-rule-them-all.html" );
	script_tag( name: "summary", value: "This host is installed with KDE Konqueror and is prone to Denial
  of Service Vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will lead to memory consumption and can result in
  a browser crash." );
	script_tag( name: "affected", value: "KDE Konqueror version 4.2.4 and prior." );
	script_tag( name: "insight", value: "The flaw occurs due to an error while processing Select object whose length
  property contains a large integer value." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: FALSE )){
	exit( 0 );
}
ver = infos["version"];
loc = infos["location"];
if(version_is_less_equal( version: ver, test_version: "4.2.4" )){
	report = report_fixed_ver( installed_version: ver, fixed_version: "WillNotFix", install_path: loc );
	security_message( port: 0, data: report );
}
exit( 0 );

