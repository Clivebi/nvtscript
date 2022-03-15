if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1607-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841187" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-10-12 09:20:39 +0530 (Fri, 12 Oct 2012)" );
	script_cve_id( "CVE-2012-2127", "CVE-2012-2137" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1607-1" );
	script_name( "Ubuntu Update for linux USN-1607-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU11\\.10" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1607-1" );
	script_tag( name: "affected", value: "linux on Ubuntu 11.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Vadim Ponomarev discovered a flaw in the Linux kernel causing a reference
  leak when PID namespaces are used. A remote attacker could exploit this
  flaw causing a denial of service. (CVE-2012-2127)

  A flaw was found in how the Linux kernel's KVM (Kernel-based Virtual
  Machine) subsystem handled MSI (Message Signaled Interrupts). A local
  unprivileged user could exploit this flaw to cause a denial of service or
  potentially elevate privileges. (CVE-2012-2137)" );
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
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "linux-image-3.0.0-26-generic", ver: "3.0.0-26.43", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.0.0-26-generic-pae", ver: "3.0.0-26.43", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.0.0-26-omap", ver: "3.0.0-26.43", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.0.0-26-powerpc", ver: "3.0.0-26.43", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.0.0-26-powerpc-smp", ver: "3.0.0-26.43", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.0.0-26-powerpc64-smp", ver: "3.0.0-26.43", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.0.0-26-server", ver: "3.0.0-26.43", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.0.0-26-virtual", ver: "3.0.0-26.43", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

