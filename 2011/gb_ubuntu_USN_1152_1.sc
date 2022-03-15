if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1152-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840680" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-06-20 08:37:08 +0200 (Mon, 20 Jun 2011)" );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:S/C:C/I:N/A:N" );
	script_xref( name: "USN", value: "1152-1" );
	script_cve_id( "CVE-2011-1486", "CVE-2010-2238", "CVE-2011-2178" );
	script_name( "Ubuntu Update for libvirt USN-1152-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.10|10\\.04 LTS|11\\.04)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1152-1" );
	script_tag( name: "affected", value: "libvirt on Ubuntu 11.04,
  Ubuntu 10.10,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that libvirt did not use thread-safe error reporting. A
  remote attacker could exploit this to cause a denial of service via
  application crash. (CVE-2011-1486)

  Eric Blake discovered that libvirt had an off-by-one error which could
  be used to reopen disk probing and bypass the fix for CVE-2010-2238. A
  privileged attacker in the guest could exploit this to read arbitrary files
  on the host. This issue only affected Ubuntu 11.04. By default, guests are
  confined by an AppArmor profile which provided partial protection against
  this flaw. (CVE-2011-2178)" );
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
	if(( res = isdpkgvuln( pkg: "libvirt-bin", ver: "0.8.3-1ubuntu18", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libvirt0", ver: "0.8.3-1ubuntu18", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libvirt-bin", ver: "0.7.5-5ubuntu27.13", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libvirt0", ver: "0.7.5-5ubuntu27.13", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "libvirt-bin", ver: "0.8.8-1ubuntu6.2", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libvirt0", ver: "0.8.8-1ubuntu6.2", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

