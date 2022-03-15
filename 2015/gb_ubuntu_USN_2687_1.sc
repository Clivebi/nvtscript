if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842390" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-07-30 05:14:14 +0200 (Thu, 30 Jul 2015)" );
	script_cve_id( "CVE-2015-3290", "CVE-2015-1333", "CVE-2015-3291", "CVE-2015-5157" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux-lts-trusty USN-2687-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-lts-trusty'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Andy Lutomirski discovered a flaw in the
Linux kernel's handling of nested NMIs (non-maskable interrupts). An unprivileged
local user could exploit this flaw to cause a denial of service (system crash) or
potentially escalate their privileges. (CVE-2015-3290)

Colin King discovered a flaw in the add_key function of the Linux kernel's
keyring subsystem. A local user could exploit this flaw to cause a denial
of service (memory exhaustion). (CVE-2015-1333)

Andy Lutomirski discovered a flaw that allows user to cause the Linux
kernel to ignore some NMIs (non-maskable interrupts). A local unprivileged
user could exploit this flaw to potentially cause the system to miss
important NMIs resulting in unspecified effects. (CVE-2015-3291)

Andy Lutomirski and Petr Matousek discovered that an NMI (non-maskable
interrupt) that interrupts userspace and encounters an IRET fault is
incorrectly handled by the Linux kernel. An unprivileged local user could
exploit this flaw to cause a denial of service (kernel OOPs), corruption,
or potentially escalate privileges on the system. (CVE-2015-5157)" );
	script_tag( name: "affected", value: "linux-lts-trusty on Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2687-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2687-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-59-generic", ver: "3.13.0-59.98~precise1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-59-generic-lpae", ver: "3.13.0-59.98~precise1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

