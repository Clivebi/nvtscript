if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1140-2/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840673" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-06-06 16:56:27 +0200 (Mon, 06 Jun 2011)" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1140-2" );
	script_cve_id( "CVE-2009-0887", "CVE-2010-3316", "CVE-2010-3430", "CVE-2010-3431", "CVE-2010-3435", "CVE-2010-3853", "CVE-2010-4706", "CVE-2010-4707" );
	script_name( "Ubuntu Update for pam USN-1140-2" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.10|10\\.04 LTS|11\\.04|8\\.04 LTS)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1140-2" );
	script_tag( name: "affected", value: "pam on Ubuntu 11.04,
  Ubuntu 10.10,
  Ubuntu 10.04 LTS,
  Ubuntu 8.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "USN-1140-1 fixed vulnerabilities in PAM. A regression was found that caused
  cron to stop working with a 'Module is unknown' error. As a result, systems
  configured with automatic updates will not receive updates until cron is
  restarted, these updates are installed or the system is rebooted. This
  update fixes the problem.

  We apologize for the inconvenience.

  Original advisory details:

  Marcus Granado discovered that PAM incorrectly handled configuration files
  with non-ASCII usernames. A remote attacker could use this flaw to cause a
  denial of service, or possibly obtain login access with a different users
  username. This issue only affected Ubuntu 8.04 LTS. (CVE-2009-0887)

  It was discovered that the PAM pam_xauth, pam_env and pam_mail modules
  incorrectly handled dropping privileges when performing operations. A local
  attacker could use this flaw to read certain arbitrary files, and access
  other sensitive information. (CVE-2010-3316, CVE-2010-3430, CVE-2010-3431,
  CVE-2010-3435)

  It was discovered that the PAM pam_namespace module incorrectly cleaned the
  environment during execution of the namespace.init script. A local attacker
  could use this flaw to possibly gain privileges. (CVE-2010-3853)

  It was discovered that the PAM pam_xauth module incorrectly handled certain
  failures. A local attacker could use this flaw to delete certain unintended
  files. (CVE-2010-4706)

  It was discovered that the PAM pam_xauth module incorrectly verified
  certain file properties. A local attacker could use this flaw to cause a
  denial of service. (CVE-2010-4707)" );
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
	if(( res = isdpkgvuln( pkg: "libpam-modules", ver: "1.1.1-4ubuntu2.3", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpam0g", ver: "1.1.1-4ubuntu2.3", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libpam-modules", ver: "1.1.1-2ubuntu5.3", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpam0g", ver: "1.1.1-2ubuntu5.3", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "libpam-modules", ver: "1.1.2-2ubuntu8.3", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpam0g", ver: "1.1.2-2ubuntu8.3", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU8.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libpam-modules", ver: "0.99.7.1-5ubuntu6.4", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpam0g", ver: "0.99.7.1-5ubuntu6.4", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

