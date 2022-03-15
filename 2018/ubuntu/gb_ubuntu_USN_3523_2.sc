if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843418" );
	script_version( "2021-06-04T11:00:20+0000" );
	script_tag( name: "last_modification", value: "2021-06-04 11:00:20 +0000 (Fri, 04 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-11 07:38:59 +0100 (Thu, 11 Jan 2018)" );
	script_cve_id( "CVE-2017-5754", "CVE-2017-17863", "CVE-2017-16995", "CVE-2017-17862", "CVE-2017-17864" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-03-16 01:29:00 +0000 (Fri, 16 Mar 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux-azure USN-3523-2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-azure'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "USN-3523-1 fixed vulnerabilities in the
  Linux kernel for Ubuntu 17.10. This update provides the corresponding updates
  for the Linux Hardware Enablement (HWE) kernel from Ubuntu 17.10 for Ubuntu
  16.04 LTS. Jann Horn discovered that microprocessors utilizing speculative
  execution and indirect branch prediction may allow unauthorized memory reads via
  sidechannel attacks. This flaw is known as Meltdown. A local attacker could use
  this to expose sensitive information, including kernel memory. (CVE-2017-5754)
  Jann Horn discovered that the Berkeley Packet Filter (BPF) implementation in the
  Linux kernel did not properly check the relationship between pointer values and
  the BPF stack. A local attacker could use this to cause a denial of service
  (system crash) or possibly execute arbitrary code. (CVE-2017-17863) Jann Horn
  discovered that the Berkeley Packet Filter (BPF) implementation in the Linux
  kernel improperly performed sign extension in some situations. A local attacker
  could use this to cause a denial of service (system crash) or possibly execute
  arbitrary code. (CVE-2017-16995) Alexei Starovoitov discovered that the Berkeley
  Packet Filter (BPF) implementation in the Linux kernel contained a
  branch-pruning logic issue around unreachable code. A local attacker could use
  this to cause a denial of service. (CVE-2017-17862) Jann Horn discovered that
  the Berkeley Packet Filter (BPF) implementation in the Linux kernel mishandled
  pointer data values in some situations. A local attacker could use this to
  expose sensitive information (kernel memory). (CVE-2017-17864)" );
	script_tag( name: "affected", value: "linux-azure on Ubuntu 16.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3523-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3523-2/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.04 LTS" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "linux-image-4.13.0-1005-azure", ver: "4.13.0-1005.7", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.13.0-1006-gcp", ver: "4.13.0-1006.9", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.13.0-1015-oem", ver: "4.13.0-1015.16", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.13.0-26-generic", ver: "4.13.0-26.29~16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.13.0-26-generic-lpae", ver: "4.13.0-26.29~16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.13.0-26-lowlatency", ver: "4.13.0-26.29~16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-azure", ver: "4.13.0.1005.6", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-gcp", ver: "4.13.0.1006.8", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic-hwe-16.04", ver: "4.13.0.26.46", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic-lpae-hwe-16.04", ver: "4.13.0.26.46", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-gke", ver: "4.13.0.1006.8", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-lowlatency-hwe-16.04", ver: "4.13.0.26.46", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-oem", ver: "4.13.0.1015.18", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

