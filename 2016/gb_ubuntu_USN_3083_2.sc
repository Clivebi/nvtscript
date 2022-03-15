if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842887" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-09-20 05:41:42 +0200 (Tue, 20 Sep 2016)" );
	script_cve_id( "CVE-2016-3841", "CVE-2015-8767" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux-lts-trusty USN-3083-2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-lts-trusty'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "USN-3083-1 fixed vulnerabilities in the Linux
  kernel for Ubuntu 14.04 LTS. This update provides the corresponding updates for
  the Linux Hardware Enablement (HWE) kernel from Ubuntu 14.04 LTS for Ubuntu
  12.04 LTS.

Dmitry Vyukov discovered that the IPv6 implementation in the Linux kernel
did not properly handle options data, including a use-after-free. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2016-3841)

It was discovered that a race condition existed when handling heartbeat-
timeout events in the SCTP implementation of the Linux kernel. A remote
attacker could use this to cause a denial of service. (CVE-2015-8767)" );
	script_tag( name: "affected", value: "linux-lts-trusty on Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3083-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3083-2/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-96-generic", ver: "3.13.0-96.143~precise1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.13.0-96-generic-lpae", ver: "3.13.0-96.143~precise1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

