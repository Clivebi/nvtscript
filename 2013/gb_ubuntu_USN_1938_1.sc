if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841540" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2013-09-06 09:37:32 +0530 (Fri, 06 Sep 2013)" );
	script_cve_id( "CVE-2013-1060", "CVE-2013-2140", "CVE-2013-2232", "CVE-2013-2234", "CVE-2013-4162", "CVE-2013-4163" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Ubuntu Update for linux USN-1938-1" );
	script_tag( name: "affected", value: "linux on Ubuntu 13.04" );
	script_tag( name: "insight", value: "Vasily Kulikov discovered a flaw in the Linux Kernel's perf tool that
allows for privilege escalation. A local could exploit this flaw to run
commands as root when using the perf tool. (CVE-2013-1060)

A flaw was discovered in the Xen subsystem of the Linux kernel when it
provides a guest OS read-only access to disks that support TRIM or SCSI
UNMAP. A privileged user in the guest OS could exploit this flaw to
destroy data on the disk. (CVE-2013-2140)

A flaw was discovered in the Linux kernel when an IPv6 socket is used to
connect to an IPv4 destination. A unprivileged local user could exploit
this flaw to cause a denial of service (system crash). (CVE-2013-2232)

An information leak was discovered in the IPSec key_socket implementation
in the Linux kernel. An local user could exploit this flaw to examine
potentially sensitive information in kernel memory. (CVE-2013-2234)

Hannes Frederic Sowa discovered a flaw in the setsockopt UDP_CORK option
in the Linux kernel's IPv6 stack. A local user could exploit this flaw to
cause a denial of service (system crash). (CVE-2013-4162)

Hannes Frederic Sowa discovered a flaw in the IPv6 subsystem of the Linux
kernel when the IPV6_MTU setsockopt option has been specified in
combination with the UDP_CORK option. A local user could exploit this flaw
to cause a denial of service (system crash). (CVE-2013-4163)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "1938-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1938-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU13\\.04" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU13.04"){
	if(( res = isdpkgvuln( pkg: "linux-image-3.8.0-30-generic", ver: "3.8.0-30.44", rls: "UBUNTU13.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

