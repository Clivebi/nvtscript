if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843312" );
	script_version( "2021-09-10T10:01:38+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 10:01:38 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-09-19 07:43:00 +0200 (Tue, 19 Sep 2017)" );
	script_cve_id( "CVE-2017-1000251", "CVE-2016-10044", "CVE-2016-10200", "CVE-2016-7097", "CVE-2016-8650", "CVE-2016-9083", "CVE-2016-9084", "CVE-2016-9178", "CVE-2016-9191", "CVE-2016-9604", "CVE-2016-9754", "CVE-2017-5970", "CVE-2017-6214", "CVE-2017-6346", "CVE-2017-6951", "CVE-2017-7187", "CVE-2017-7472", "CVE-2017-7541" );
	script_tag( name: "cvss_base", value: "7.7" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-03 19:00:00 +0000 (Wed, 03 Jun 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux USN-3422-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that a buffer overflow
  existed in the Bluetooth stack of the Linux kernel when handling L2CAP
  configuration responses. A physically proximate attacker could use this to cause
  a denial of service (system crash). (CVE-2017-1000251) It was discovered that
  the asynchronous I/O (aio) subsystem of the Linux kernel did not properly set
  permissions on aio memory mappings in some situations. An attacker could use
  this to more easily exploit other vulnerabilities. (CVE-2016-10044) Baozeng Ding
  and Andrey Konovalov discovered a race condition in the L2TPv3 IP Encapsulation
  implementation in the Linux kernel. A local attacker could use this to cause a
  denial of service (system crash) or possibly execute arbitrary code.
  (CVE-2016-10200) Andreas Gruenbacher and Jan Kara discovered that the filesystem
  implementation in the Linux kernel did not clear the setgid bit during a
  setxattr call. A local attacker could use this to possibly elevate group
  privileges. (CVE-2016-7097) Sergej Schumilo, Ralf Spenneberg, and Hendrik
  Schwartke discovered that the key management subsystem in the Linux kernel did
  not properly allocate memory in some situations. A local attacker could use this
  to cause a denial of service (system crash). (CVE-2016-8650) Vlad Tsyrklevich
  discovered an integer overflow vulnerability in the VFIO PCI driver for the
  Linux kernel. A local attacker with access to a vfio PCI device file could use
  this to cause a denial of service (system crash) or possibly execute arbitrary
  code. (CVE-2016-9083, CVE-2016-9084) It was discovered that an information leak
  existed in __get_user_asm_ex() in the Linux kernel. A local attacker could use
  this to expose sensitive information. (CVE-2016-9178) CAI Qian discovered that
  the sysctl implementation in the Linux kernel did not properly perform reference
  counting in some situations. An unprivileged attacker could use this to cause a
  denial of service (system hang). (CVE-2016-9191) It was discovered that the
  keyring implementation in the Linux kernel in some situations did not prevent
  special internal keyrings from being joined by userspace keyrings. A privileged
  local attacker could use this to bypass module verification. (CVE-2016-9604) It
  was discovered that an integer overflow existed in the trace subsystem of the
  Linux kernel. A local privileged attacker could use this to cause a denial of
  service (system crash). (CVE-2016-9754) Andrey Konovalov discovered that the
  IPv4 implementation in the Linux kernel did not properly handle invalid IP
  options in some situations. An attacker could use this to cause a denial of
  service or possibly ex ... Description truncated, for more information please
  check the Reference URL" );
	script_tag( name: "affected", value: "linux on Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3422-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3422-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU14\\.04 LTS" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-132-generic", ver: "3.13.0-132.181", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-132-generic-lpae", ver: "3.13.0-132.181", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-132-lowlatency", ver: "3.13.0-132.181", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-132-powerpc-e500", ver: "3.13.0-132.181", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-132-powerpc-e500mc", ver: "3.13.0-132.181", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-132-powerpc-smp", ver: "3.13.0-132.181", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-132-powerpc64-emb", ver: "3.13.0-132.181", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-132-powerpc64-smp", ver: "3.13.0-132.181", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic", ver: "3.13.0.132.141", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic-lpae", ver: "3.13.0.132.141", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-lowlatency", ver: "3.13.0.132.141", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc-e500", ver: "3.13.0.132.141", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc-e500mc", ver: "3.13.0.132.141", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc-smp", ver: "3.13.0.132.141", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc64-emb", ver: "3.13.0.132.141", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc64-smp", ver: "3.13.0.132.141", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

