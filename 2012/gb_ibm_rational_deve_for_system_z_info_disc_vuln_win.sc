if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802687" );
	script_version( "$Revision: 12978 $" );
	script_cve_id( "CVE-2012-4862" );
	script_bugtraq_id( 56725 );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2019-01-08 15:15:07 +0100 (Tue, 08 Jan 2019) $" );
	script_tag( name: "creation_date", value: "2012-12-21 19:17:26 +0530 (Fri, 21 Dec 2012)" );
	script_name( "IBM Rational Developer for System z Information Disclosure Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/51401/" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/79919" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21617886" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Successful exploitation could allow local users to obtain sensitive information
  via unspecified vectors." );
	script_tag( name: "affected", value: "IBM Rational Developer for System z version 7.1 through 8.5.1 on Windows" );
	script_tag( name: "insight", value: "The flaw is due to error in the application, which does not properly store the
  SSL certificate password." );
	script_tag( name: "solution", value: "Upgrade to IBM Rational Developer for System z version 8.5.2 or later." );
	script_tag( name: "summary", value: "This host is installed with IBM Rational Developer for System z and
  is prone information disclosure vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.ibm.com/developerworks/downloads/r/rdz/index.html" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
swFile = "IBM_Rational_Developer_for_zEnterprise";
ibmKey = "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall" + "\\\\RDzEnt-IBM Software Delivery Platform";
swPkgVers = make_list( "7.1",
	 "7.5",
	 "7.5.1",
	 "7.5.1.3",
	 "7.5.1.4",
	 "7.6",
	 "7.6.1",
	 "7.6.2",
	 "7.6.2.2",
	 "7.6.2.3",
	 "7.6.2.4",
	 "8.0.1",
	 "8.0.2",
	 "8.0.3",
	 "8.0.3.1",
	 "8.0.3.2",
	 "8.0.3.3",
	 "8.5",
	 "8.5.0",
	 "8.5.0.1",
	 "8.5.1" );
if(!registry_key_exists( key: ibmKey )){
	exit( 0 );
}
rdzPath = registry_get_sz( key: ibmKey, item: "DisplayIcon" );
if(!rdzPath){
	exit( 0 );
}
if(rdzPath && IsMatchRegexp( rdzPath, "\\\\SDP\\\\rdz" )){
	for ext in make_list( ".",
		 "-" ) {
		for swPkgVer in swPkgVers {
			swFilePath = rdzPath - "RDz.ico" + "properties\\\\version\\\\" + swFile + ext + swPkgVer + ".swtag";
			rdzFile = smb_read_file( fullpath: swFilePath, offset: 0, count: 250 );
			if(rdzFile && IsMatchRegexp( rdzFile, "ProductVersion>[0-9\\.]+<" ) && IsMatchRegexp( rdzFile, "ProductName>IBM Rational Developer for zEnterprise" )){
				rdzVer = eregmatch( pattern: "ProductVersion>([0-9\\.]+)<", string: rdzFile );
				if(version_in_range( version: rdzVer[1], test_version: "7.1", test_version2: "8.5.1" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
		}
	}
}

