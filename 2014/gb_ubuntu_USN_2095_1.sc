if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841697" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-02-03 14:07:40 +0530 (Mon, 03 Feb 2014)" );
	script_cve_id( "CVE-2014-0038" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Ubuntu Update for linux-lts-saucy USN-2095-1" );
	script_tag( name: "affected", value: "linux-lts-saucy on Ubuntu 12.04 LTS" );
	script_tag( name: "insight", value: "Pageexec reported a bug in the Linux kernel's recvmsg syscall
when called from code using the x32 ABI. An unprivileged local user could
exploit this flaw to cause a denial of service (system crash) or gain
administrator privileges." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2095-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2095-1/" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-3.11.0-15-generic", ver: "3.11.0-15.25~precise1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.11.0-15-generic-lpae", ver: "3.11.0-15.25~precise1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

