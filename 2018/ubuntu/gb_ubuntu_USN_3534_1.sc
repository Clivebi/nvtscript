if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843422" );
	script_version( "2021-06-03T02:00:18+0000" );
	script_tag( name: "last_modification", value: "2021-06-03 02:00:18 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-18 07:36:12 +0100 (Thu, 18 Jan 2018)" );
	script_cve_id( "CVE-2018-1000001", "CVE-2017-1000409", "CVE-2017-1000408", "CVE-2017-15670", "CVE-2017-15804", "CVE-2017-16997", "CVE-2017-17426" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-15 13:28:00 +0000 (Thu, 15 Oct 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for glibc USN-3534-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'glibc'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the GNU C library did
  not properly handle all of the possible return values from the kernel getcwd(2)
  syscall. A local attacker could potentially exploit this to execute arbitrary
  code in setuid programs and gain administrative privileges. (CVE-2018-1000001) A
  memory leak was discovered in the _dl_init_paths() function in the GNU C library
  dynamic loader. A local attacker could potentially exploit this with a specially
  crafted value in the LD_HWCAP_MASK environment variable, in combination with
  CVE-2017-1000409 and another vulnerability on a system with hardlink protections
  disabled, in order to gain administrative privileges. (CVE-2017-1000408) A
  heap-based buffer overflow was discovered in the _dl_init_paths() function in
  the GNU C library dynamic loader. A local attacker could potentially exploit
  this with a specially crafted value in the LD_LIBRARY_PATH environment variable,
  in combination with CVE-2017-1000408 and another vulnerability on a system with
  hardlink protections disabled, in order to gain administrative privileges.
  (CVE-2017-1000409) An off-by-one error leading to a heap-based buffer overflow
  was discovered in the GNU C library glob() implementation. An attacker could
  potentially exploit this to cause a denial of service or execute arbitrary code
  via a maliciously crafted pattern. (CVE-2017-15670) A heap-based buffer overflow
  was discovered during unescaping of user names with the ~ operator in the GNU C
  library glob() implementation. An attacker could potentially exploit this to
  cause a denial of service or execute arbitrary code via a maliciously crafted
  pattern. (CVE-2017-15804) It was discovered that the GNU C library dynamic
  loader mishandles RPATH and RUNPATH containing $ORIGIN for privileged (setuid or
  AT_SECURE) programs. A local attacker could potentially exploit this by
  providing a specially crafted library in the current working directory in order
  to gain administrative privileges. (CVE-2017-16997) It was discovered that the
  GNU C library malloc() implementation could return a memory block that is too
  small if an attempt is made to allocate an object whose size is close to
  SIZE_MAX, resulting in a heap-based overflow. An attacker could potentially
  exploit this to cause a denial of service or execute arbitrary code. This issue
  only affected Ubuntu 17.10. (CVE-2017-17426)" );
	script_tag( name: "affected", value: "glibc on Ubuntu 17.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3534-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3534-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|17\\.10|16\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "libc6:amd64", ver: "2.19-0ubuntu6.14", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libc6:i386", ver: "2.19-0ubuntu6.14", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.10"){
	if(( res = isdpkgvuln( pkg: "libc6:amd64", ver: "2.26-0ubuntu2.1", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libc6:i386", ver: "2.26-0ubuntu2.1", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libc6:amd64", ver: "2.23-0ubuntu10", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libc6:i386", ver: "2.23-0ubuntu10", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

