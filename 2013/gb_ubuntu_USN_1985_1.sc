if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841576" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-10-03 10:20:45 +0530 (Thu, 03 Oct 2013)" );
	script_cve_id( "CVE-2013-2099", "CVE-2013-4238" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_name( "Ubuntu Update for python3.3 USN-1985-1" );
	script_tag( name: "affected", value: "python3.3 on Ubuntu 13.04,
  Ubuntu 12.10" );
	script_tag( name: "insight", value: "Florian Weimer discovered that Python incorrectly handled matching multiple
wildcards in ssl certificate hostnames. An attacker could exploit this to
cause Python to consume resources, resulting in a denial of service.
(CVE-2013-2099)

Ryan Sleevi discovered that Python did not properly handle certificates
with NULL characters in the Subject Alternative Name field. An attacker
could exploit this to perform a man in the middle attack to view sensitive
information or alter encrypted communications. (CVE-2013-4238)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "1985-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1985-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python3.3'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.10|13\\.04)" );
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
	if(( res = isdpkgvuln( pkg: "python3.3", ver: "3.3.0-1ubuntu0.1", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "python3.3-minimal", ver: "3.3.0-1ubuntu0.1", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.04"){
	if(( res = isdpkgvuln( pkg: "python3.3", ver: "3.3.1-1ubuntu5.2", rls: "UBUNTU13.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "python3.3-minimal", ver: "3.3.1-1ubuntu5.2", rls: "UBUNTU13.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

