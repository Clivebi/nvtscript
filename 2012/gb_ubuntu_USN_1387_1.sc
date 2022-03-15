if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1387-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840912" );
	script_version( "2021-08-27T12:01:24+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 12:01:24 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-03-07 11:19:13 +0530 (Wed, 07 Mar 2012)" );
	script_cve_id( "CVE-2011-1927", "CVE-2011-0716", "CVE-2011-3353", "CVE-2011-3619", "CVE-2011-4622", "CVE-2012-0038", "CVE-2012-0044" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-29 15:27:00 +0000 (Wed, 29 Jul 2020)" );
	script_xref( name: "USN", value: "1387-1" );
	script_name( "Ubuntu Update for linux-lts-backport-maverick USN-1387-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU10\\.04 LTS" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1387-1" );
	script_tag( name: "affected", value: "linux-lts-backport-maverick on Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Aristide Fattori and Roberto Paleari reported a flaw in the Linux kernel's
  handling of IPv4 icmp packets. A remote user could exploit this to cause a
  denial of service. (CVE-2011-1927)

  A flaw was found in the Linux Ethernet bridge's handling of IGMP (Internet
  Group Management Protocol) packets. An unprivileged local user could
  exploit this flaw to crash the system. (CVE-2011-0716)

  Han-Wen Nienhuys reported a flaw in the FUSE kernel module. A local user
  who can mount a FUSE file system could cause a denial of service.
  (CVE-2011-3353)

  A flaw was discovered in the Linux kernel's AppArmor security interface
  when invalid information was written to it. An unprivileged local user
  could use this to cause a denial of service on the system. (CVE-2011-3619)

  A flaw was found in KVM's Programmable Interval Timer (PIT). When a virtual
  interrupt control is not available a local user could use this to cause a
  denial of service by starting a timer. (CVE-2011-4622)

  A flaw was discovered in the XFS filesystem. If a local user mounts a
  specially crafted XFS image it could potential execute arbitrary code on
  the system. (CVE-2012-0038)

  Chen Haogang discovered an integer overflow that could result in memory
  corruption. A local unprivileged user could use this to crash the system.
  (CVE-2012-0044)" );
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
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.35-32-generic", ver: "2.6.35-32.66~lucid1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.35-32-generic-pae", ver: "2.6.35-32.66~lucid1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.35-32-server", ver: "2.6.35-32.66~lucid1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.35-32-virtual", ver: "2.6.35-32.66~lucid1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

