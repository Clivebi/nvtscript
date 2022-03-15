if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1589-2/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841254" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-12-18 10:04:54 +0530 (Tue, 18 Dec 2012)" );
	script_cve_id( "CVE-2012-3404", "CVE-2012-3405", "CVE-2012-3406", "CVE-2012-3480" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "USN", value: "1589-2" );
	script_name( "Ubuntu Update for glibc USN-1589-2" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU8\\.04 LTS" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1589-2" );
	script_tag( name: "affected", value: "glibc on Ubuntu 8.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "USN-1589-1 fixed vulnerabilities in the GNU C Library. One of the updates
  exposed a regression in the floating point parser. This update fixes the
  problem.

  We apologize for the inconvenience.

  Original advisory details:

  It was discovered that positional arguments to the printf() family
  of functions were not handled properly in the GNU C Library. An
  attacker could possibly use this to cause a stack-based buffer
  overflow, creating a denial of service or possibly execute arbitrary
  code. (CVE-2012-3404, CVE-2012-3405, CVE-2012-3406)
  It was discovered that multiple integer overflows existed in the
  strtod(), strtof() and strtold() functions in the GNU C Library. An
  attacker could possibly use this to trigger a stack-based buffer
  overflow, creating a denial of service or possibly execute arbitrary
  code. (CVE-2012-3480)" );
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
if(release == "UBUNTU8.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libc6", ver: "2.7-10ubuntu8.3", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

