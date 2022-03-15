CPE = "cpe:/a:ibm:lotus_domino";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803973" );
	script_version( "2020-09-22T09:01:10+0000" );
	script_tag( name: "last_modification", value: "2020-09-22 09:01:10 +0000 (Tue, 22 Sep 2020)" );
	script_tag( name: "creation_date", value: "2013-12-05 13:26:26 +0530 (Thu, 05 Dec 2013)" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_cve_id( "CVE-2013-4055", "CVE-2013-4051", "CVE-2013-4050" );
	script_bugtraq_id( 63578, 63577, 63576 );
	script_name( "IBM Lotus Domino Web Administrator Cross Site Scripting Vulnerability" );
	script_tag( name: "summary", value: "IBM Lotus Domino is prone to cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
  to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "insight", value: "The flaw is in the webadmin.nsf file in Domino Web Administrator which fails
  to validate user supplied input properly." );
	script_tag( name: "affected", value: "IBM Lotus Domino 8.5 and 9.0." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote authenticated users to hijack
  the authentication of unspecified victims." );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/86544" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21652988" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_hcl_domino_consolidation.sc" );
	script_mandatory_keys( "hcl/domino/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_equal( version: version, test_version: "8.5.0" ) || version_is_equal( version: version, test_version: "9.0.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 0 );

