if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841781" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-05-02 10:10:56 +0530 (Fri, 02 May 2014)" );
	script_cve_id( "CVE-2014-0049", "CVE-2014-0069" );
	script_tag( name: "cvss_base", value: "7.4" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:M/Au:S/C:C/I:C/A:C" );
	script_name( "Ubuntu Update for linux-lts-saucy USN-2177-1" );
	script_tag( name: "affected", value: "linux-lts-saucy on Ubuntu 12.04 LTS" );
	script_tag( name: "insight", value: "A flaw was discovered in the Kernel Virtual Machine (KVM)
subsystem of the Linux kernel. A guest OS user could exploit this flaw to
execute arbitrary code on the host OS. (CVE-2014-0049)

Al Viro discovered an error in how CIFS in the Linux kernel handles
uncached write operations. An unprivileged local user could exploit this
flaw to cause a denial of service (system crash), obtain sensitive
information from kernel memory, or possibly gain privileges.
(CVE-2014-0069)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2177-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2177-1/" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-3.11.0-20-generic", ver: "3.11.0-20.34~precise1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.11.0-20-generic-lpae", ver: "3.11.0-20.34~precise1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

