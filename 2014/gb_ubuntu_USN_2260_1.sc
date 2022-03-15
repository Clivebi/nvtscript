if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841870" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-07-01 21:42:04 +0530 (Tue, 01 Jul 2014)" );
	script_cve_id( "CVE-2014-0196", "CVE-2014-3153", "CVE-2014-1738", "CVE-2014-1737", "CVE-2014-0077", "CVE-2014-2568", "CVE-2014-2851", "CVE-2014-3122" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Ubuntu Update for linux-lts-trusty USN-2260-1" );
	script_tag( name: "affected", value: "linux-lts-trusty on Ubuntu 12.04 LTS" );
	script_tag( name: "insight", value: "A flaw was discovered in the Linux kernel's pseudo tty (pty)
device. An unprivileged user could exploit this flaw to cause a denial of
service (system crash) or potentially gain administrator privileges.
(CVE-2014-0196)

Pinkie Pie discovered a flaw in the Linux kernel's futex subsystem. An
unprivileged local user could exploit this flaw to cause a denial of
service (system crash) or gain administrative privileges. (CVE-2014-3153)

Matthew Daley reported an information leak in the floppy disk driver of the
Linux kernel. An unprivileged local user could exploit this flaw to obtain
potentially sensitive information from kernel memory. (CVE-2014-1738)

Matthew Daley reported a flaw in the handling of ioctl commands by the
floppy disk driver in the Linux kernel. An unprivileged local user could
exploit this flaw to gain administrative privileges if the floppy disk
module is loaded. (CVE-2014-1737)

A flaw was discovered in the handling of network packets when mergeable
buffers are disabled for virtual machines in the Linux kernel. Guest OS
users may exploit this flaw to cause a denial of service (host OS crash) or
possibly gain privilege on the host OS. (CVE-2014-0077)

An information leak was discovered in the netfilter subsystem of the Linux
kernel. An attacker could exploit this flaw to obtain sensitive information
from kernel memory. (CVE-2014-2568)

A flaw was discovered in the Linux kernel's ping sockets. An unprivileged
local user could exploit this flaw to cause a denial of service (system
crash) or possibly gain privileges via a crafted application.
(CVE-2014-2851)

Sasha Levin reported a bug in the Linux kernel's virtual memory management
subsystem. An unprivileged local user could exploit this flaw to cause a
denial of service (system crash). (CVE-2014-3122)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2260-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2260-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-lts-trusty'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-30-generic", ver: "3.13.0-30.54~precise2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-30-generic-lpae", ver: "3.13.0-30.54~precise2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

