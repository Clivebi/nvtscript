if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842475" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-10-02 07:12:59 +0200 (Fri, 02 Oct 2015)" );
	script_cve_id( "CVE-2015-5707", "CVE-2015-6252", "CVE-2015-6526" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux-ti-omap4 USN-2760-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-ti-omap4'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that an integer overflow
error existed in the SCSI generic (sg) driver in the Linux kernel. A local attacker
with write permission to a SCSI generic device could use this to cause a denial of
service (system crash) or potentially escalate their privileges.
(CVE-2015-5707)

Marc-Andr&#233  Lureau discovered that the vhost driver did not properly
release the userspace provided log file descriptor. A privileged attacker
could use this to cause a denial of service (resource exhaustion).
(CVE-2015-6252)

It was discovered that the Linux kernel's perf subsystem did not bound
callchain backtraces on PowerPC 64. A local attacker could use this to
cause a denial of service. (CVE-2015-6526)" );
	script_tag( name: "affected", value: "linux-ti-omap4 on Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2760-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2760-1/" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-3.2.0-1471-omap4", ver: "3.2.0-1471.92", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

