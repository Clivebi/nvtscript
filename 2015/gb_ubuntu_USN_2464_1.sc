if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842058" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-01-23 12:58:43 +0100 (Fri, 23 Jan 2015)" );
	script_cve_id( "CVE-2014-9322", "CVE-2014-8134", "CVE-2014-7842", "CVE-2014-8369", "CVE-2014-9090" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Ubuntu Update for linux-ti-omap4 USN-2464-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-ti-omap4'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Andy Lutomirski discovered that the Linux
kernel does not properly handle faults associated with the Stack Segment (SS)
register in the x86 architecture. A local attacker could exploit this flaw to gain
administrative privileges. (CVE-2014-9322)

An information leak in the Linux kernel was discovered that could leak the
high 16 bits of the kernel stack address on 32-bit Kernel Virtual Machine
(KVM) paravirt guests. A user in the guest OS could exploit this leak to
obtain information that could potentially be used to aid in attacking the
kernel. (CVE-2014-8134)

A race condition with MMIO and PIO transactions in the KVM (Kernel Virtual
Machine) subsystem of the Linux kernel was discovered. A guest OS user
could exploit this flaw to cause a denial of service (guest OS crash) via a
specially crafted application. (CVE-2014-7842)

The KVM (kernel virtual machine) subsystem of the Linux kernel
miscalculates the number of memory pages during the handling of a mapping
failure. A guest OS user could exploit this to cause a denial of service
(host OS page unpinning) or possibly have unspecified other impact by
leveraging guest OS privileges. (CVE-2014-8369)

Andy Lutomirski discovered that the Linux kernel does not properly handle
faults associated with the Stack Segment (SS) register on the x86
architecture. A local attacker could exploit this flaw to cause a denial of
service (panic). (CVE-2014-9090)" );
	script_tag( name: "affected", value: "linux-ti-omap4 on Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2464-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2464-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU12\\.04 LTS" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "linux-image-3.2.0-1458-omap4", ver: "3.2.0-1458.78", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

