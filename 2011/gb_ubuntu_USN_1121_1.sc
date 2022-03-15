if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1121-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840635" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-05-10 14:04:15 +0200 (Tue, 10 May 2011)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1121-1" );
	script_cve_id( "CVE-2011-0079", "CVE-2011-0081", "CVE-2011-0069", "CVE-2011-0070", "CVE-2011-1202" );
	script_name( "Ubuntu Update for firefox USN-1121-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU11\\.04" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1121-1" );
	script_tag( name: "affected", value: "firefox on Ubuntu 11.04" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Boris Zbarsky, Gary Kwong, Jesse Ruderman, Michael Wu, and Ted Mielczarek
  discovered multiple memory vulnerabilities. An attacker could exploit these
  to possibly run arbitrary code as the user running Firefox. (CVE-2011-0079)

  It was discovered that there was a vulnerability in the memory handling of
  certain types of content. An attacker could exploit this to possibly run
  arbitrary code as the user running Firefox. (CVE-2011-0081)

  It was discovered that Firefox incorrectly handled certain JavaScript
  requests. An attacker could exploit this to possibly run arbitrary code as
  the user running Firefox. (CVE-2011-0069)

  Ian Beer discovered a vulnerability in the memory handling of a certain
  types of documents. An attacker could exploit this to possibly run
  arbitrary code as the user running Firefox. (CVE-2011-0070)

  Chris Evans discovered a vulnerability in Firefox's XSLT generate-id()
  function. An attacker could possibly use this vulnerability to make other
  attacks more reliable. (CVE-2011-1202)" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "4.0.1+build1+nobinonly-0ubuntu0.11.04.1", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

