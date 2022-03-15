if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843099" );
	script_version( "2021-09-15T12:01:38+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 12:01:38 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-03-21 05:50:56 +0100 (Tue, 21 Mar 2017)" );
	script_cve_id( "CVE-2015-8982", "CVE-2015-8983", "CVE-2015-8984", "CVE-2016-1234", "CVE-2015-5180", "CVE-2016-3706", "CVE-2016-4429", "CVE-2016-5417", "CVE-2016-6323" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for glibc USN-3239-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'glibc'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the GNU C Library
  incorrectly handled the strxfrm() function. An attacker could use this issue to
  cause a denial of service or possibly execute arbitrary code. This issue only
  affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2015-8982) It was
  discovered that an integer overflow existed in the _IO_wstr_overflow() function
  of the GNU C Library. An attacker could use this to cause a denial of service or
  possibly execute arbitrary code. This issue only affected Ubuntu 12.04 LTS and
  Ubuntu 14.04 LTS. (CVE-2015-8983) It was discovered that the fnmatch() function
  in the GNU C Library did not properly handle certain malformed patterns. An
  attacker could use this to cause a denial of service. This issue only affected
  Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2015-8984) Alexander Cherepanov
  discovered a stack-based buffer overflow in the glob implementation of the GNU C
  Library. An attacker could use this to specially craft a directory layout and
  cause a denial of service. (CVE-2016-1234) Florian Weimer discovered a NULL
  pointer dereference in the DNS resolver of the GNU C Library. An attacker could
  use this to cause a denial of service. (CVE-2015-5180) Michael Petlan discovered
  an unbounded stack allocation in the getaddrinfo() function of the GNU C
  Library. An attacker could use this to cause a denial of service.
  (CVE-2016-3706) Aldy Hernandez discovered an unbounded stack allocation in the
  sunrpc implementation in the GNU C Library. An attacker could use this to cause
  a denial of service. (CVE-2016-4429) Tim Ruehsen discovered that the
  getaddrinfo() implementation in the GNU C Library did not properly track memory
  allocations. An attacker could use this to cause a denial of service. This issue
  only affected Ubuntu 16.04 LTS. (CVE-2016-5417) Andreas Schwab discovered that
  the GNU C Library on ARM 32-bit platforms did not properly set up execution
  contexts. An attacker could use this to cause a denial of service.
  (CVE-2016-6323)" );
	script_tag( name: "affected", value: "glibc on Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3239-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3239-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|12\\.04 LTS|16\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "libc6:i386", ver: "2.19-0ubuntu6.10", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libc6:amd64", ver: "2.19-0ubuntu6.10", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libc6:i386", ver: "2.15-0ubuntu10.16", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libc6:amd64", ver: "2.15-0ubuntu10.16", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libc6:i386", ver: "2.23-0ubuntu6", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libc6:amd64", ver: "2.23-0ubuntu6", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

