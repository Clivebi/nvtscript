if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841736" );
	script_version( "2020-08-31T07:00:15+0000" );
	script_tag( name: "last_modification", value: "2020-08-31 07:00:15 +0000 (Mon, 31 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-03-12 09:30:13 +0530 (Wed, 12 Mar 2014)" );
	script_cve_id( "CVE-2014-1690", "CVE-2014-1874", "CVE-2014-2038" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:C" );
	script_name( "Ubuntu Update for linux-lts-saucy USN-2137-1" );
	script_tag( name: "affected", value: "linux-lts-saucy on Ubuntu 12.04 LTS" );
	script_tag( name: "insight", value: "An information leak was discovered in the Linux kernel when
built with the NetFilter Connection Tracking (NF_CONNTRACK) support for IRC
protocol (NF_NAT_IRC). A remote attacker could exploit this flaw to obtain
potentially sensitive kernel information when communicating over a client-
to-client IRC connection(/dcc) via a NAT-ed network. (CVE-2014-1690)

Matthew Thode reported a denial of service vulnerability in the Linux
kernel when SELinux support is enabled. A local user with the CAP_MAC_ADMIN
capability (and the SELinux mac_admin permission if running in enforcing
mode) could exploit this flaw to cause a denial of service (kernel crash).
(CVE-2014-1874)

An information leak was discovered in the Linux kernel's NFS filesystem. A
local users with write access to an NFS share could exploit this flaw to
obtain potential sensitive information from kernel memory. (CVE-2014-2038)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2137-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2137-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-lts-saucy'
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
	if(( res = isdpkgvuln( pkg: "linux-image-3.11.0-18-generic", ver: "3.11.0-18.32~precise1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.11.0-18-generic-lpae", ver: "3.11.0-18.32~precise1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

