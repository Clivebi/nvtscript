if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842699" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-03-18 05:31:59 +0100 (Fri, 18 Mar 2016)" );
	script_cve_id( "CVE-2013-7041", "CVE-2014-2583", "CVE-2015-3238" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for pam USN-2935-3" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pam'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "USN-2935-1 fixed vulnerabilities in PAM.
  The updates contained a packaging change that prevented upgrades in certain
  multiarch environments. USN-2935-2 intended to fix the problem but was incomplete
  for Ubuntu 12.04 LTS. This update fixes the problem in Ubuntu 12.04 LTS.

  We apologize for the inconvenience.

  Original advisory details:

  It was discovered that the PAM pam_userdb module incorrectly used a
  case-insensitive method when comparing hashed passwords. A local attacker
  could possibly use this issue to make brute force attacks easier. This
  issue only affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2013-7041)

  Sebastian Krahmer discovered that the PAM pam_timestamp module incorrectly
  performed filtering. A local attacker could use this issue to create
  arbitrary files, or possibly bypass authentication. This issue only
  affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2014-2583)

  Sebastien Macke discovered that the PAM pam_unix module incorrectly handled
  large passwords. A local attacker could possibly use this issue in certain
  environments to enumerate usernames or cause a denial of service.
  (CVE-2015-3238)" );
	script_tag( name: "affected", value: "pam on Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2935-3" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2935-3/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
	if(( res = isdpkgvuln( pkg: "libpam-modules:i386", ver: "1.1.3-7ubuntu2.3", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpam-modules:amd64", ver: "1.1.3-7ubuntu2.3", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

