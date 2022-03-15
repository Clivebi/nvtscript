if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841615" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-11-08 10:58:22 +0530 (Fri, 08 Nov 2013)" );
	script_cve_id( "CVE-2013-1057", "CVE-2013-1058" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_name( "Ubuntu Update for maas USN-2013-1" );
	script_tag( name: "affected", value: "maas on Ubuntu 13.04,
  Ubuntu 12.10,
  Ubuntu 12.04 LTS" );
	script_tag( name: "insight", value: "It was discovered that maas-import-pxe-files incorrectly
loaded configuration information from the current working directory. A local
attacker could execute code as an administrator if maas-import-pxe-files
were run from an attacker-controlled directory. (CVE-2013-1057)

It was discovered that maas-import-pxe-files doesn't cryptographically
verify downloaded content. An attacker could modify images without
detection. (CVE-2013-1058)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2013-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2013-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'maas'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|12\\.10|13\\.04)" );
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
	if(( res = isdpkgvuln( pkg: "maas-cluster-controller", ver: "1.2+bzr1373+dfsg-0ubuntu1~12.04.4", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "maas-cluster-controller", ver: "1.2+bzr1373+dfsg-0ubuntu1.1", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.04"){
	if(( res = isdpkgvuln( pkg: "maas-cluster-controller", ver: "1.3+bzr1461+dfsg-0ubuntu2.3", rls: "UBUNTU13.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

