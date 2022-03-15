CPE = "cpe:/a:quickheal:antivirus_pro";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804181" );
	script_version( "$Revision: 11401 $" );
	script_cve_id( "CVE-2013-6767" );
	script_bugtraq_id( 64402 );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-15 10:45:50 +0200 (Sat, 15 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2013-12-30 20:51:30 +0530 (Mon, 30 Dec 2013)" );
	script_name( "Quick Heal Antivirus Pro 'pepoly.dll' Stack Buffer Overflow Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Quick Heal Antivirus Pro and is prone to stack
buffer overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "insight", value: "The flaw is due to improper bounds checking by the 'pepoly.dll' module." );
	script_tag( name: "affected", value: "Quick Heal AntiVirus Pro version 7.0.0.1 and probably other versions." );
	script_tag( name: "impact", value: "Successful exploitation will allow a local attacker to cause a stack-based
buffer overflow, resulting in a denial of service or execution of arbitrary
code." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/30374" );
	script_xref( name: "URL", value: "http://www.vulnerability-lab.com/get_content.php?id=1171" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_quick_heal_av_detect.sc" );
	script_mandatory_keys( "QuickHeal/Antivirus6432/Pro/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!qhVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_equal( version: qhVer, test_version: "7.0.0.1" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}

