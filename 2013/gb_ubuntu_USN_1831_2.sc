if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841444" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-05-31 09:57:55 +0530 (Fri, 31 May 2013)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_name( "Ubuntu Update for nova USN-1831-2" );
	script_xref( name: "USN", value: "1831-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1831-2/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nova'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU12\\.10" );
	script_tag( name: "affected", value: "nova on Ubuntu 12.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "USN-1831-1 fixed a vulnerability in OpenStack Nova. The upstream fix
  introduced a regression where instances using uncached QCOW2 images would
  fail to start. This update fixes the problem.

  We apologize for the inconvenience.

  Original advisory details:

  Loganathan Parthipan discovered that Nova did not verify the size of QCOW2
  instance storage. An authenticated attacker could exploit this to cause a
  denial of service by creating an image with a large virtual size with
  little data, then filling the virtual disk." );
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
	if(( res = isdpkgvuln( pkg: "python-nova", ver: "2012.2.3-0ubuntu2.2", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

