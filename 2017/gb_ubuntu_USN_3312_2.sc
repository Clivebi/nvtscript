if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843199" );
	script_version( "2021-09-15T08:01:41+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 08:01:41 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-06-08 06:03:28 +0200 (Thu, 08 Jun 2017)" );
	script_cve_id( "CVE-2016-7917", "CVE-2016-8632", "CVE-2016-9604", "CVE-2017-0605", "CVE-2017-2596", "CVE-2017-2671", "CVE-2017-6001", "CVE-2017-7472", "CVE-2017-7645", "CVE-2017-7889", "CVE-2017-7895", "CVE-2016-7913", "CVE-2016-9084", "CVE-2017-7618", "CVE-2016-9083" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux-lts-xenial USN-3312-2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-lts-xenial'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "USN-3312-1 fixed vulnerabilities in the
  Linux kernel for Ubuntu 16.04 LTS. This update provides the corresponding
  updates for the Linux Hardware Enablement (HWE) kernel from Ubuntu 16.04 LTS for
  Ubuntu 14.04 LTS. It was discovered that the netfilter netlink implementation in
  the Linux kernel did not properly validate batch messages. A local attacker with
  the CAP_NET_ADMIN capability could use this to expose sensitive information or
  cause a denial of service. (CVE-2016-7917) Qian Zhang discovered a heap-based
  buffer overflow in the tipc_msg_build() function in the Linux kernel. A local
  attacker could use to cause a denial of service (system crash) or possibly
  execute arbitrary code with administrative privileges. (CVE-2016-8632) It was
  discovered that the keyring implementation in the Linux kernel in some
  situations did not prevent special internal keyrings from being joined by
  userspace keyrings. A privileged local attacker could use this to bypass module
  verification. (CVE-2016-9604) It was discovered that a buffer overflow existed
  in the trace subsystem in the Linux kernel. A privileged local attacker could
  use this to execute arbitrary code. (CVE-2017-0605) Dmitry Vyukov discovered
  that KVM implementation in the Linux kernel improperly emulated the VMXON
  instruction. A local attacker in a guest OS could use this to cause a denial of
  service (memory consumption) in the host OS. (CVE-2017-2596) Daniel Jiang
  discovered that a race condition existed in the ipv4 ping socket implementation
  in the Linux kernel. A local privileged attacker could use this to cause a
  denial of service (system crash). (CVE-2017-2671) Di Shen discovered that a race
  condition existed in the perf subsystem of the Linux kernel. A local attacker
  could use this to cause a denial of service or possibly gain administrative
  privileges. (CVE-2017-6001) Eric Biggers discovered a memory leak in the keyring
  implementation in the Linux kernel. A local attacker could use this to cause a
  denial of service (memory consumption). (CVE-2017-7472) Sabrina Dubroca
  discovered that the asynchronous cryptographic hash (ahash) implementation in
  the Linux kernel did not properly handle a full request queue. A local attacker
  could use this to cause a denial of service (infinite recursion).
  (CVE-2017-7618) Tuomas Haanp&#228 &#228 and Ari Kauppi discovered that the NFSv2
  and NFSv3 server implementations in the Linux kernel did not properly handle
  certain long RPC replies. A remote attacker could use this to cause a denial of
  service (system crash). (CVE-2017-7645) Tommi Rantala and Brad Spengler
  discovered that the memory ... Description truncated, for more information
  please check the Reference URL" );
	script_tag( name: "affected", value: "linux-lts-xenial on Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3312-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3312-2/" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-79-generic", ver: "4.4.0-79.100~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-79-generic-lpae", ver: "4.4.0-79.100~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-79-lowlatency", ver: "4.4.0-79.100~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-79-powerpc-e500mc", ver: "4.4.0-79.100~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-79-powerpc-smp", ver: "4.4.0-79.100~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-79-powerpc64-emb", ver: "4.4.0-79.100~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-79-powerpc64-smp", ver: "4.4.0-79.100~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic-lpae-lts-xenial", ver: "4.4.0.79.64", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic-lts-xenial", ver: "4.4.0.79.64", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-lowlatency-lts-xenial", ver: "4.4.0.79.64", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc-e500mc-lts-xenial", ver: "4.4.0.79.64", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc-smp-lts-xenial", ver: "4.4.0.79.64", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc64-emb-lts-xenial", ver: "4.4.0.79.64", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-powerpc64-smp-lts-xenial", ver: "4.4.0.79.64", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

