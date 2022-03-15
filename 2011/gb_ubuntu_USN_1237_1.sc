if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1237-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840794" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-10-31 13:45:00 +0100 (Mon, 31 Oct 2011)" );
	script_xref( name: "USN", value: "1237-1" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2011-3148", "CVE-2011-3149", "CVE-2011-3628" );
	script_name( "Ubuntu Update for pam USN-1237-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.10|10\\.04 LTS|11\\.04|8\\.04 LTS)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1237-1" );
	script_tag( name: "affected", value: "pam on Ubuntu 11.04,
  Ubuntu 10.10,
  Ubuntu 10.04 LTS,
  Ubuntu 8.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Kees Cook discovered that the PAM pam_env module incorrectly handled
  certain malformed environment files. A local attacker could use this flaw
  to cause a denial of service, or possibly gain privileges. The default
  compiler options for affected releases should reduce the vulnerability to a
  denial of service. (CVE-2011-3148)

  Kees Cook discovered that the PAM pam_env module incorrectly handled
  variable expansion. A local attacker could use this flaw to cause a denial
  of service. (CVE-2011-3149)

  Stephane Chazelas discovered that the PAM pam_motd module incorrectly
  cleaned the environment during execution of the motd scripts. In certain
  environments, a local attacker could use this to execute arbitrary code
  as root, and gain privileges." );
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
	if(( res = isdpkgvuln( pkg: "libpam-modules", ver: "1.1.1-4ubuntu2.4", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libpam-modules", ver: "1.1.1-2ubuntu5.4", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "libpam-modules", ver: "1.1.2-2ubuntu8.4", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU8.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libpam-modules", ver: "0.99.7.1-5ubuntu6.5", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

