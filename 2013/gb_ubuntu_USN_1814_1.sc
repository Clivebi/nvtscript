if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841413" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-06-14 12:55:04 +0530 (Fri, 14 Jun 2013)" );
	script_cve_id( "CVE-2012-6548", "CVE-2012-6549", "CVE-2013-0913", "CVE-2013-1848", "CVE-2013-1860", "CVE-2013-2634", "CVE-2013-2635" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Ubuntu Update for linux-ti-omap4 USN-1814-1" );
	script_xref( name: "USN", value: "1814-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1814-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-ti-omap4'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU12\\.10" );
	script_tag( name: "affected", value: "linux-ti-omap4 on Ubuntu 12.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Mathias Krause discovered an information leak in the Linux kernel's UDF
  file system implementation. A local user could exploit this flaw to examine
  some of the kernel's heap memory. (CVE-2012-6548)

  Mathias Krause discovered an information leak in the Linux kernel's ISO
  9660 CDROM file system driver. A local user could exploit this flaw to
  examine some of the kernel's heap memory. (CVE-2012-6549)

  An integer overflow was discovered in the Direct Rendering Manager (DRM)
  subsystem for the i915 video driver in the Linux kernel. A local user could
  exploit this flaw to cause a denial of service (crash) or potentially
  escalate privileges. (CVE-2013-0913)

  A format-string bug was discovered in the Linux kernel's ext3 filesystem
  driver. A local user could exploit this flaw to possibly escalate
  privileges on the system. (CVE-2013-1848)

  A buffer overflow was discovered in the Linux Kernel's USB subsystem for
  devices reporting the cdc-wdm class. A specially crafted USB device when
  plugged-in could cause a denial of service (system crash) or possibly
  execute arbitrary code. (CVE-2013-1860)

  An information leak in the Linux kernel's dcb netlink interface was
  discovered. A local user could obtain sensitive information by examining
  kernel stack memory. (CVE-2013-2634)

  A kernel stack information leak was discovered in the RTNETLINK component
  of the Linux kernel. A local user could read sensitive information from the
  kernel stack. (CVE-2013-2635)" );
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
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "linux-image-3.5.0-223-omap4", ver: "3.5.0-223.34", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

