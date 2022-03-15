CPE = "cpe:/a:adobe:acrobat_reader";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801095" );
	script_version( "2020-04-27T09:00:11+0000" );
	script_cve_id( "CVE-2009-4324" );
	script_bugtraq_id( 37331 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-27 09:00:11 +0000 (Mon, 27 Apr 2020)" );
	script_tag( name: "creation_date", value: "2009-12-21 07:14:17 +0100 (Mon, 21 Dec 2009)" );
	script_name( "Adobe Reader Multimeda Doc.media.newPlayer Code Execution Vulnerability (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Reader and is prone to Doc.media.newPlayer
  Remote Code Execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "There exists a flaw in the JavaScript module doc.media object while sending a
  null argument to the newPlayer() method as the exploitation method makes use of a vpointer that has not been initialized." );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to execute arbitrary code and
  compromise a user's system." );
	script_tag( name: "affected", value: "Adobe Reader version 9.2.0 and prior." );
	script_tag( name: "solution", value: "Upgrade Adobe Reader version 9.3.2 or later.

  Workaround: Disable JavaScript execution from the Adobe Acrobat/Reader product
  configuration menu settings." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.f-secure.com/weblog/archives/00001836.html" );
	script_xref( name: "URL", value: "http://extraexploit.blogspot.com/search/label/CVE-2009-4324" );
	script_xref( name: "URL", value: "http://www.shadowserver.org/wiki/pmwiki.php/Calendar/20091214" );
	script_xref( name: "URL", value: "http://blogs.adobe.com/psirt/2009/12/new_adobe_reader_and_acrobat_v.html" );
	script_xref( name: "URL", value: "http://downloads.securityfocus.com/vulnerabilities/exploits/adobe_media_newplayer.rb" );
	script_xref( name: "URL", value: "http://vrt-sourcefire.blogspot.com/2009/12/adobe-reader-medianewplayer-analysis.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_adobe_prdts_detect_lin.sc" );
	script_mandatory_keys( "Adobe/Reader/Linux/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(readerVer = get_app_version( cpe: CPE )){
	if(version_is_less_equal( version: readerVer, test_version: "9.2.0" )){
		report = report_fixed_ver( installed_version: readerVer, vulnerable_range: "Less than or equal to 9.2.0" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}

