CPE = "cpe:/a:mantisbt:mantisbt";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804676" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2013-1810", "CVE-2013-0197" );
	script_bugtraq_id( 57468, 57456 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2014-07-14 11:59:38 +0530 (Mon, 14 Jul 2014)" );
	script_name( "MantisBT Multiple Cross-Site Scripting Vulnerabilities -01 July14" );
	script_tag( name: "summary", value: "This host is installed with MantisBT and is prone to multiple cross-site
scripting vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Input passed via the 'name' parameter to manage_proj_cat_add.php script when
creating a category is not properly sanitised in core/summary_api.php script
before being used.

  - Input passed to the 'match_type' POST parameter in bugs/search.php script is
not properly sanitised before being returned to the user." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attacker to execute arbitrary script
code in a user's browser within the trust relationship between their browser and
the server." );
	script_tag( name: "affected", value: "MantisBT version 1.2.12, prior versions may also be affected." );
	script_tag( name: "solution", value: "Upgrade to MantisBT version 1.2.13 or later." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/51853" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/81394" );
	script_xref( name: "URL", value: "http://www.mantisbt.org/bugs/view.php?id=15384" );
	script_xref( name: "URL", value: "http://www.mantisbt.org/bugs/view.php?id=15373" );
	script_xref( name: "URL", value: "http://hauntit.blogspot.de/2013/01/en-mantis-bug-tracker-1212-persistent.html" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "mantis_detect.sc" );
	script_mandatory_keys( "mantisbt/detected" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!manPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!manVer = get_app_version( cpe: CPE, port: manPort )){
	exit( 0 );
}
if(version_is_less_equal( version: manVer, test_version: "1.2.12" )){
	report = report_fixed_ver( installed_version: manVer, fixed_version: "1.2.13" );
	security_message( port: manPort, data: report );
	exit( 0 );
}
exit( 99 );

