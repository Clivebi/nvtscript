CPE = "cpe:/a:foxitsoftware:phantompdf";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805363" );
	script_version( "2020-11-25T09:16:10+0000" );
	script_cve_id( "CVE-2015-2790" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-11-25 09:16:10 +0000 (Wed, 25 Nov 2020)" );
	script_tag( name: "creation_date", value: "2015-04-14 18:11:48 +0530 (Tue, 14 Apr 2015)" );
	script_name( "Foxit PhantomPDF Denial of Service Vulnerability" );
	script_tag( name: "summary", value: "The host is installed with Foxit PhantomPDF
  and is prone to Denial of Service Vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to Ubyte Size in a
  DataSubBlock structure or LZWMinimumCodeSize in a GIF image." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause a denial-of-service attacks." );
	script_tag( name: "affected", value: "Foxit PhantomPDF version prior to
  7.1." );
	script_tag( name: "solution", value: "Upgrade to Foxit PhantomPDF version
  7.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1031877" );
	script_xref( name: "URL", value: "http://www.foxitsoftware.com/support/security_bulletins.php#FRD-24" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_dependencies( "gb_foxit_phantom_reader_detect.sc" );
	script_mandatory_keys( "foxit/phantompdf/ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!foxitVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: foxitVer, test_version: "7.1.0.0" )){
	report = "Installed version: " + foxitVer + "\n" + "Fixed version:     7.1" + "\n";
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

