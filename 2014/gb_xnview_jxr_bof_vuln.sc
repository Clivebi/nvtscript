CPE = "cpe:/a:xnview:xnview";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804349" );
	script_version( "$Revision: 11402 $" );
	script_cve_id( "CVE-2013-3938" );
	script_bugtraq_id( 66187 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2014-03-26 13:19:16 +0530 (Wed, 26 Mar 2014)" );
	script_name( "XnView JXR File Handling Buffer Overflow Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with XnView and is prone to buffer overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to improper validation of 'NUM_ELEMENTS' field in IFD_ENTRY
structures when parsing JXR files." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to conduct denial of
service or potentially execute arbitrary code on the target machine by
enticing the user of XnView to open a specially crafted file." );
	script_tag( name: "affected", value: "XnView version 2.13" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/56172" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_xnview_detect_win.sc" );
	script_mandatory_keys( "XnView/Win/Ver" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_equal( version: version, test_version: "2.13" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}

