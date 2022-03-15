if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842241" );
	script_version( "2020-10-27T15:01:28+0000" );
	script_tag( name: "last_modification", value: "2020-10-27 15:01:28 +0000 (Tue, 27 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-06-11 06:31:20 +0200 (Thu, 11 Jun 2015)" );
	script_cve_id( "CVE-2015-2150", "CVE-2015-2830", "CVE-2015-3331", "CVE-2015-3636", "CVE-2015-4167" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux-ti-omap4 USN-2632-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-ti-omap4'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Jan Beulich discovered the Xen virtual
machine subsystem of the Linux kernel did not properly restrict access to PCI
command registers. A local guest user could exploit this flaw to cause a denial
of service (host crash). (CVE-2015-2150)

A privilege escalation was discovered in the fork syscall via the int80
entry on 64 bit kernels with 32 bit emulation support. An unprivileged
local attacker could exploit this flaw to increase their privileges on the
system. (CVE-2015-2830)

A memory corruption issue was discovered in AES decryption when using the
Intel AES-NI accelerated code path. A remote attacker could exploit this
flaw to cause a denial of service (system crash) or potentially escalate
privileges on Intel base machines with AEC-GCM mode IPSec security
association. (CVE-2015-3331)

Wen Xu discovered a use-after-free flaw in the Linux kernel's ipv4 ping
support. A local user could exploit this flaw to cause a denial of service
(system crash) or gain administrative privileges on the system.
(CVE-2015-3636)

Carl H Lunde discovered missing sanity checks in the Linux kernel's UDF
file system (CONFIG_UDF_FS). A local attack could exploit this flaw to cause
a denial of service (system crash) by using a corrupted filesystem image.
(CVE-2015-4167)" );
	script_tag( name: "affected", value: "linux-ti-omap4 on Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2632-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2632-1/" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-3.2.0-1465-omap4", ver: "3.2.0-1465.85", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

