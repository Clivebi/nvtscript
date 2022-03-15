CPE = "cpe:/a:barracudadrive:barracudadrive";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804612" );
	script_version( "$Revision: 11402 $" );
	script_cve_id( "CVE-2014-3807", "CVE-2014-4335" );
	script_bugtraq_id( 67428, 68079 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2014-06-02 13:48:59 +0530 (Mon, 02 Jun 2014)" );
	script_name( "BarracudaDrive Multiple XSS Vulnerabilities -03 June14" );
	script_tag( name: "summary", value: "This host is running BarracudaDrive and is prone to multiple XSS
vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist as,

  - Input passed via the 'blog' parameter to 'private/manage/', 'bloggeruser'
parameter to 'private/manage/', Input passed via the 'bloggerpasswd'
parameter to 'private/manage/', Input passed via the 'host' and 'password'
parameters is not  properly verified before it is given to server for
processing." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary
HTML and script code in a user's browser session in the context of a
vulnerable site." );
	script_tag( name: "affected", value: "BarracudaDrive version 6.7.2" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/93899" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/126645" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/127128" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_barracuda_drive_detect.sc" );
	script_mandatory_keys( "BarracudaDrive/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!bdPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
bdVer = get_app_version( cpe: CPE, port: bdPort );
if(!bdVer){
	exit( 0 );
}
if(version_is_equal( version: bdVer, test_version: "6.7.2" )){
	security_message( bdPort );
	exit( 0 );
}

