if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841718" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-02-20 15:16:53 +0530 (Thu, 20 Feb 2014)" );
	script_cve_id( "CVE-2013-6383", "CVE-2013-7263", "CVE-2013-7264", "CVE-2013-7265", "CVE-2013-7281" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Ubuntu Update for linux-ec2 USN-2108-1" );
	script_tag( name: "affected", value: "linux-ec2 on Ubuntu 10.04 LTS" );
	script_tag( name: "insight", value: "A flaw was discovered in the Linux kernel's compat ioctls for Adaptec
AACRAID scsi raid devices. An unprivileged local user could send
administrative commands to these devices potentially compromising the data
stored on the device. (CVE-2013-6383)

mpd reported an information leak in the recvfrom, recvmmsg, and recvmsg
system calls in the Linux kernel. An unprivileged local user could exploit
this flaw to obtain sensitive information from kernel stack memory.
(CVE-2013-7263)

mpb reported an information leak in the Layer Two Tunneling Protocol (l2tp)
of the Linux kernel. A local user could exploit this flaw to obtain
sensitive information from kernel stack memory. (CVE-2013-7264)

mpb reported an information leak in the Phone Network protocol (phonet) in
the Linux kernel. A local user could exploit this flaw to obtain sensitive
information from kernel stack memory. (CVE-2013-7265)

mpb reported an information leak in the Low-Rate Wireless Personal Area
Networks support (IEEE 802.15.4) in the Linux kernel. A local user could
exploit this flaw to obtain sensitive information from kernel stack memory.
(CVE-2013-7281)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2108-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2108-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-ec2'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU10\\.04 LTS" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.32-361-ec2", ver: "2.6.32-361.74", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

