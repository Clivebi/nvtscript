if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842761" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-05-17 16:25:20 +0200 (Tue, 17 May 2016)" );
	script_cve_id( "CVE-2016-3713", "CVE-2016-0758" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux USN-2979-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "David Matlack discovered that the
  Kernel-based Virtual Machine (KVM) implementation in the Linux kernel did
  not properly restrict variable Memory Type Range Registers (MTRR) in KVM guests.
  A privileged user in a guest VM could use this to cause a denial of service
  (system crash) in the host, expose sensitive information from the host, or
  possibly gain administrative privileges in the host. (CVE-2016-3713)

  Philip Pettersson discovered that the Linux kernel's ASN.1 DER decoder did
  not properly process certificate files with tags of indefinite length. A
  local unprivileged attacker could use this to cause a denial of service
  (system crash) or possibly execute arbitrary code with administrative
  privileges. (CVE-2016-0758)" );
	script_tag( name: "affected", value: "linux on Ubuntu 16.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2979-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2979-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-22-generic", ver: "4.4.0-22.40", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-22-generic-lpae", ver: "4.4.0-22.40", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-22-lowlatency", ver: "4.4.0-22.40", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-22-powerpc-e500mc", ver: "4.4.0-22.40", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-22-powerpc-smp", ver: "4.4.0-22.40", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-22-powerpc64-emb", ver: "4.4.0-22.40", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-22-powerpc64-smp", ver: "4.4.0-22.40", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

