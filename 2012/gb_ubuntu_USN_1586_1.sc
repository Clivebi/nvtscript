if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1586-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841172" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-10-03 09:24:29 +0530 (Wed, 03 Oct 2012)" );
	script_cve_id( "CVE-2012-0035", "CVE-2012-3479" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1586-1" );
	script_name( "Ubuntu Update for emacs23 USN-1586-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|11\\.10)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1586-1" );
	script_tag( name: "affected", value: "emacs23 on Ubuntu 12.04 LTS,
  Ubuntu 11.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Hiroshi Oota discovered that Emacs incorrectly handled search paths. If a
  user were tricked into opening a file with Emacs, a local attacker could
  execute arbitrary Lisp code with the privileges of the user invoking the
  program. (CVE-2012-0035)

  Paul Ling discovered that Emacs incorrectly handled certain eval forms in
  local-variable sections. If a user were tricked into opening a specially
  crafted file with Emacs, a remote attacker could execute arbitrary Lisp
  code with the privileges of the user invoking the program. (CVE-2012-3479)" );
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
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "emacs23", ver: "23.3+1-1ubuntu9.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "emacs23-common", ver: "23.3+1-1ubuntu9.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "emacs23", ver: "23.3+1-1ubuntu4.1", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "emacs23-common", ver: "23.3+1-1ubuntu4.1", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

