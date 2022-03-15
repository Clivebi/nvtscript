if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801351" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-06-09 08:34:53 +0200 (Wed, 09 Jun 2010)" );
	script_cve_id( "CVE-2010-2127" );
	script_bugtraq_id( 40339 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "JV2 Folder Gallery 'lang_file' Parameter Remote File Inclusion Vulnerability" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/58807" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/12688" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/1005-exploits/jv2foldergallery-rfi.txt" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_jv2_folder_gallery_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "jv2_folder_gallery/detected" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to execute
  arbitrary PHP code via a URL in the lang_file parameter." );
	script_tag( name: "affected", value: "JV2 Folder Gallery version 3.1 and prior." );
	script_tag( name: "insight", value: "The flaw is due to improper sanitization of user supplied input
  in 'lang_file' parameter in 'gallery/gallery.php' while including external files for processing." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running JV2 Folder Gallery and is prone to remote
  file inclusion vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
vfgPort = http_get_port( default: 80 );
vfgVer = get_kb_item( "www/" + vfgPort + "/JV2/Folder/Gallery" );
if(!vfgVer){
	exit( 0 );
}
vfgVer = eregmatch( pattern: "^(.+) under (/.*)$", string: vfgVer );
if(vfgVer[1] != NULL){
	if(version_is_less_equal( version: vfgVer[1], test_version: "3.1" )){
		security_message( vfgPort );
	}
}

