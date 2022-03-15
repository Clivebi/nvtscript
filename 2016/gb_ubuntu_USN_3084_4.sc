if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842886" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-09-20 05:41:37 +0200 (Tue, 20 Sep 2016)" );
	script_cve_id( "CVE-2016-6136", "CVE-2016-5412", "CVE-2016-6156" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:S/C:N/I:N/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux-snapdragon USN-3084-4" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-snapdragon'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Pengfei Wang discovered a race condition
  in the audit subsystem in the Linux kernel. A local attacker could use this
  to corrupt audit logs or disrupt system-call auditing. (CVE-2016-6136)

It was discovered that the powerpc and powerpc64 hypervisor-mode KVM
implementation in the Linux kernel for did not properly maintain state
about transactional memory. An unprivileged attacker in a guest could cause
a denial of service (CPU lockup) in the host OS. (CVE-2016-5412)

Pengfei Wang discovered a race condition in the Chrome OS embedded
controller device driver in the Linux kernel. A local attacker could use
this to cause a denial of service (system crash). (CVE-2016-6156)" );
	script_tag( name: "affected", value: "linux-snapdragon on Ubuntu 16.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3084-4" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3084-4/" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-1026-snapdragon", ver: "4.4.0-1026.29", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

