if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1482-3/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841117" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-08-17 10:22:08 +0530 (Fri, 17 Aug 2012)" );
	script_cve_id( "CVE-2012-1457", "CVE-2012-1459", "CVE-2012-1458" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_xref( name: "USN", value: "1482-3" );
	script_name( "Ubuntu Update for clamav USN-1482-3" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|11\\.10|11\\.04)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1482-3" );
	script_tag( name: "affected", value: "clamav on Ubuntu 12.04 LTS,
  Ubuntu 11.10,
  Ubuntu 11.04" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "USN-1482-1 fixed vulnerabilities in ClamAV. The updated package could
  fail to properly scan files in some situations.  This update fixes
  the problem.

  We apologize for the inconvenience.

  Original advisory details:

  It was discovered that ClamAV incorrectly handled certain malformed TAR
  archives. A remote attacker could create a specially-crafted TAR file
  containing malware that could escape being detected. (CVE-2012-1457,
  CVE-2012-1459)

  It was discovered that ClamAV incorrectly handled certain malformed CHM
  files. A remote attacker could create a specially-crafted CHM file
  containing malware that could escape being detected. (CVE-2012-1458)" );
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
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "clamav", ver: "0.97.5+dfsg-1ubuntu0.12.04.3", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libclamav6", ver: "0.97.5+dfsg-1ubuntu0.12.04.3", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "clamav", ver: "0.97.5+dfsg-1ubuntu0.11.10.3", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libclamav6", ver: "0.97.5+dfsg-1ubuntu0.11.10.3", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "clamav", ver: "0.97.5+dfsg-1ubuntu0.11.04.3", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libclamav6", ver: "0.97.5+dfsg-1ubuntu0.11.04.3", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

