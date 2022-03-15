if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1283-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840825" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-12-02 13:30:36 +0530 (Fri, 02 Dec 2011)" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:N/A:N" );
	script_xref( name: "USN", value: "1283-1" );
	script_cve_id( "CVE-2011-3634" );
	script_name( "Ubuntu Update for apt USN-1283-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.10|10\\.04 LTS|11\\.04|8\\.04 LTS)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1283-1" );
	script_tag( name: "affected", value: "apt on Ubuntu 11.04,
  Ubuntu 10.10,
  Ubuntu 10.04 LTS,
  Ubuntu 8.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that APT incorrectly handled the Verify-Host
  configuration option. If a remote attacker were able to perform a
  man-in-the-middle attack, this flaw could potentially be used to steal
  repository credentials. This issue only affected Ubuntu 10.04 LTS and
  10.10. (CVE-2011-3634)

  USN-1215-1 fixed a vulnerability in APT by disabling the apt-key net-update
  option. This update re-enables the option with corrected verification.
  Original advisory details:
  It was discovered that the apt-key utility incorrectly verified GPG
  keys when downloaded via the net-update option. If a remote attacker were
  able to perform a man-in-the-middle attack, this flaw could potentially be
  used to install altered packages." );
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
	if(( res = isdpkgvuln( pkg: "apt", ver: "0.8.3ubuntu7.3", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "apt", ver: "0.7.25.3ubuntu9.9", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "apt", ver: "0.8.13.2ubuntu4.3", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU8.04 LTS"){
	if(( res = isdpkgvuln( pkg: "apt", ver: "0.7.9ubuntu17.4", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

