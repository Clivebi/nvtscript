if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841766" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-04-03 12:58:11 +0530 (Thu, 03 Apr 2014)" );
	script_cve_id( "CVE-2013-4345", "CVE-2013-6382", "CVE-2014-1690" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_name( "Ubuntu Update for linux-lts-raring USN-2158-1" );
	script_tag( name: "affected", value: "linux-lts-raring on Ubuntu 12.04 LTS" );
	script_tag( name: "insight", value: "Stephan Mueller reported an error in the Linux kernel's ansi
cprng random number generator. This flaw makes it easier for a local attacker
to break cryptographic protections. (CVE-2013-4345)

Nico Golde and Fabian Yamaguchi reported buffer underflow errors in the
implementation of the XFS filesystem in the Linux kernel. A local user with
CAP_SYS_ADMIN could exploit these flaw to cause a denial of service (memory
corruption) or possibly other unspecified issues. (CVE-2013-6382)

An information leak was discovered in the Linux kernel when built with the
NetFilter Connection Tracking (NF_CONNTRACK) support for IRC protocol
(NF_NAT_IRC). A remote attacker could exploit this flaw to obtain
potentially sensitive kernel information when communicating over a client-
to-client IRC connection(/dcc) via a NAT-ed network. (CVE-2014-1690)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2158-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2158-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-lts-raring'
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
	if(( res = isdpkgvuln( pkg: "linux-image-3.8.0-38-generic", ver: "3.8.0-38.56~precise1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

