CPE = "cpe:/a:realnetworks:realplayer";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804620" );
	script_version( "$Revision: 11402 $" );
	script_cve_id( "CVE-2014-3444" );
	script_bugtraq_id( 67434 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2014-06-06 19:16:08 +0530 (Fri, 06 Jun 2014)" );
	script_name( "RealNetworks RealPlayer '.3gp' Memory Corruption Vulnerability Jun14 (Mac OS X)" );
	script_tag( name: "summary", value: "The host is installed with RealPlayer and is prone to memory corruption
vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw is due to input not being properly sanitized when handling a specially
crafted 3GP file." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to corrupt memory, causing
a denial of service or potentially allowing the execution of arbitrary code." );
	script_tag( name: "affected", value: "RealNetworks RealPlayer version 16.0.3.51 and before on Mac OS X." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/126637" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_realplayer_detect_macosx.sc" );
	script_mandatory_keys( "RealPlayer/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!realVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_in_range( version: realVer, test_version: "16.0", test_version2: "16.0.3.51" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}

