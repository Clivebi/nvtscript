if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803910" );
	script_version( "2020-11-25T09:16:10+0000" );
	script_cve_id( "CVE-2013-3299" );
	script_bugtraq_id( 60903 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-11-25 09:16:10 +0000 (Wed, 25 Nov 2020)" );
	script_tag( name: "creation_date", value: "2013-07-17 16:46:46 +0530 (Wed, 17 Jul 2013)" );
	script_name( "RealNetworks RealPlayer Denial of Service Vulnerability - July13 (Windows)" );
	script_tag( name: "impact", value: "Successful exploitation allows remote attackers to cause denial of service
  condition via crafted HTML file." );
	script_tag( name: "affected", value: "RealPlayer versions 16.0.2.32 and prior on Windows." );
	script_tag( name: "insight", value: "Flaw within the unknown function of the component HTML Handler." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "summary", value: "This host is installed with RealPlayer which is prone to Denial of
  Service vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1028732" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2013/Jul/18" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_realplayer_detect_win.sc" );
	script_mandatory_keys( "RealPlayer/Win/Ver" );
	exit( 0 );
}
require("version_func.inc.sc");
rpVer = get_kb_item( "RealPlayer/Win/Ver" );
if(!rpVer){
	exit( 0 );
}
if(version_is_less_equal( version: rpVer, test_version: "16.0.2.32" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}

