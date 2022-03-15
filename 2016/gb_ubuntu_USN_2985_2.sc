if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842775" );
	script_version( "2021-09-20T11:23:55+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 11:23:55 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-05-27 05:20:47 +0200 (Fri, 27 May 2016)" );
	script_cve_id( "CVE-2014-9761", "CVE-2013-2207", "CVE-2016-2856", "CVE-2014-8121", "CVE-2015-1781", "CVE-2015-5277", "CVE-2015-8776", "CVE-2015-8777", "CVE-2015-8778", "CVE-2015-8779", "CVE-2016-3075" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for glibc USN-2985-2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'glibc'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "USN-2985-1 fixed vulnerabilities in the
  GNU C Library. The fix for CVE-2014-9761 introduced a regression which affected
  applications that use the libm library but were not fully restarted after the
  upgrade. This update removes the fix for CVE-2014-9761 and a future update
  will be provided to address this issue.

  We apologize for the inconvenience.

  Original advisory details:

  Martin Carpenter discovered that pt_chown in the GNU C Library did not
  properly check permissions for tty files. A local attacker could use this
  to gain administrative privileges or expose sensitive information.
  (CVE-2013-2207, CVE-2016-2856)

  Robin Hack discovered that the Name Service Switch (NSS) implementation in
  the GNU C Library did not properly manage its file descriptors. An attacker
  could use this to cause a denial of service (infinite loop).
  (CVE-2014-8121)

  Joseph Myers discovered that the GNU C Library did not properly handle long
  arguments to functions returning a representation of Not a Number (NaN). An
  attacker could use this to cause a denial of service (stack exhaustion
  leading to an application crash) or possibly execute arbitrary code.
  (CVE-2014-9761)

  Arjun Shankar discovered that in certain situations the nss_dns code in the
  GNU C Library did not properly account buffer sizes when passed an
  unaligned buffer. An attacker could use this to cause a denial of service
  or possibly execute arbitrary code. (CVE-2015-1781)

  Sumit Bose and Lukas Slebodnik discovered that the Name Service
  Switch (NSS) implementation in the GNU C Library did not handle long
  lines in the files databases correctly. A local attacker could use
  this to cause a denial of service (application crash) or possibly
  execute arbitrary code. (CVE-2015-5277)

  Adam Nielsen discovered that the strftime function in the GNU C Library did
  not properly handle out-of-range argument data. An attacker could use this
  to cause a denial of service (application crash) or possibly expose
  sensitive information. (CVE-2015-8776)

  Hector Marco and Ismael Ripoll discovered that the GNU C Library allowed
  the pointer-guarding protection mechanism to be disabled by honoring the
  LD_POINTER_GUARD environment variable across privilege boundaries. A local
  attacker could use this to exploit an existing vulnerability more easily.
  (CVE-2015-8777)

  Szabolcs Nagy discovered that the hcreate functions in the GNU C Library
  did not properly check its size argument, leading to an integer overflow.
  An attacker could use to cause a denial of service (application crash) or
  possibly execute arbitrary code. (CVE-2015-8778)

  Maksymilian Arciemo ...

  Description truncated, please see the referenced URL(s) for more information." );
	script_tag( name: "affected", value: "glibc on Ubuntu 15.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2985-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2985-2/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|12\\.04 LTS|15\\.10)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libc-bin", ver: "2.19-0ubuntu6.9", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libc6:i386", ver: "2.19-0ubuntu6.9", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libc6:amd64", ver: "2.19-0ubuntu6.9", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libc6-dev:i386", ver: "2.19-0ubuntu6.9", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libc6-dev:amd64", ver: "2.19-0ubuntu6.9", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libc-bin", ver: "2.15-0ubuntu10.15", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libc6:i386", ver: "2.15-0ubuntu10.15", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libc6:amd64", ver: "2.15-0ubuntu10.15", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libc6-dev:i386", ver: "2.15-0ubuntu10.15", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libc6-dev:amd64", ver: "2.15-0ubuntu10.15", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU15.10"){
	if(( res = isdpkgvuln( pkg: "libc-bin", ver: "2.21-0ubuntu4.3", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libc6:i386", ver: "2.21-0ubuntu4.3", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libc6:amd64", ver: "2.21-0ubuntu4.3", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libc6-dev:i386", ver: "2.21-0ubuntu4.3", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libc6-dev:amd64", ver: "2.21-0ubuntu4.3", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

