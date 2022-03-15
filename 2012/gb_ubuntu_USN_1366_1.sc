if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1366-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840905" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-02-21 19:00:44 +0530 (Tue, 21 Feb 2012)" );
	script_cve_id( "CVE-2012-0210", "CVE-2012-0211", "CVE-2012-0212" );
	script_xref( name: "USN", value: "1366-1" );
	script_name( "Ubuntu Update for devscripts USN-1366-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.10|10\\.04 LTS|11\\.04|8\\.04 LTS)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1366-1" );
	script_tag( name: "affected", value: "devscripts on Ubuntu 11.04,
  Ubuntu 10.10,
  Ubuntu 10.04 LTS,
  Ubuntu 8.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Paul Wise discovered that debdiff did not properly sanitize its input when
  processing .dsc and .changes files. If debdiff processed a crafted file, an
  attacker could execute arbitrary code with the privileges of the user invoking
  the program. (CVE-2012-0210)

  Raphael Geissert discovered that debdiff did not properly sanitize its input
  when processing source packages. If debdiff processed an original source
  tarball, with crafted filenames in the top-level directory, an attacker could
  execute arbitrary code with the privileges of the user invoking the program.
  (CVE-2012-0211)

  Raphael Geissert discovered that debdiff did not properly sanitize its input
  when processing filename parameters. If debdiff processed a crafted filename
  parameter, an attacker could execute arbitrary code with the privileges of the
  user invoking the program. (CVE-2012-0212)" );
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
if(release == "UBUNTU10.10"){
	if(( res = isdpkgvuln( pkg: "devscripts", ver: "2.10.67ubuntu1.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "devscripts", ver: "2.10.61ubuntu5.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "devscripts", ver: "2.10.69ubuntu2.1", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU8.04 LTS"){
	if(( res = isdpkgvuln( pkg: "devscripts", ver: "2.10.11ubuntu5.8.04.5", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

