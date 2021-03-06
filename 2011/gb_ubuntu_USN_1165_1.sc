if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1165-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840695" );
	script_tag( name: "cvss_base", value: "7.4" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:M/Au:S/C:C/I:C/A:C" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-07-08 16:31:28 +0200 (Fri, 08 Jul 2011)" );
	script_xref( name: "USN", value: "1165-1" );
	script_cve_id( "CVE-2011-2212", "CVE-2011-2512" );
	script_name( "Ubuntu Update for qemu-kvm USN-1165-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.10|10\\.04 LTS|11\\.04)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1165-1" );
	script_tag( name: "affected", value: "qemu-kvm on Ubuntu 11.04,
  Ubuntu 10.10,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Nelson Elhage discoverd that QEMU did not properly validate certain
  virtqueue requests from the guest. An attacker could exploit this to cause
  a denial of service of the guest or possibly execute code with the
  privileges of the user invoking the program. (CVE-2011-2212)

  Stefan Hajnoczi discovered that QEMU did not properly perform integer
  comparisons when performing virtqueue input validation. An attacker could
  exploit this to cause a denial of service of the guest or possibly execute
  code with the privileges of the user invoking the program. (CVE-2011-2512)

  When using QEMU with libvirt or virtualization management software based on
  libvirt such as Eucalyptus and OpenStack, QEMU guests are individually
  isolated by an AppArmor profile by default in Ubuntu." );
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
if(release == "UBUNTU10.10"){
	if(( res = isdpkgvuln( pkg: "qemu-kvm", ver: "0.12.5+noroms-0ubuntu7.8", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-kvm-extras", ver: "0.12.5+noroms-0ubuntu7.8", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-kvm-extras-static", ver: "0.12.5+noroms-0ubuntu7.8", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "qemu-kvm", ver: "0.12.3+noroms-0ubuntu9.12", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-kvm-extras", ver: "0.12.3+noroms-0ubuntu9.12", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "qemu-kvm-extras-static", ver: "0.12.3+noroms-0ubuntu9.12", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "qemu-kvm", ver: "0.14.0+noroms-0ubuntu4.3", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

