if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1113-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840648" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-05-10 14:04:15 +0200 (Tue, 10 May 2011)" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1113-1" );
	script_cve_id( "CVE-2009-2939", "CVE-2011-0411" );
	script_name( "Ubuntu Update for postfix USN-1113-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.04 LTS|9\\.10|6\\.06 LTS|10\\.10|8\\.04 LTS)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1113-1" );
	script_tag( name: "affected", value: "postfix on Ubuntu 10.10,
  Ubuntu 10.04 LTS,
  Ubuntu 9.10,
  Ubuntu 8.04 LTS,
  Ubuntu 6.06 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that the Postfix package incorrectly granted write access
  on the PID directory to the postfix user. A local attacker could use this
  flaw to possibly conduct a symlink attack and overwrite arbitrary files.
  This issue only affected Ubuntu 6.06 LTS and 8.04 LTS. (CVE-2009-2939)

  Wietse Venema discovered that Postfix incorrectly handled cleartext
  commands after TLS is in place. A remote attacker could exploit this to
  inject cleartext commands into TLS sessions, and possibly obtain
  confidential information such as passwords. (CVE-2011-0411)" );
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
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "postfix", ver: "2.7.0-1ubuntu0.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU9.10"){
	if(( res = isdpkgvuln( pkg: "postfix", ver: "2.6.5-3ubuntu0.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU6.06 LTS"){
	if(( res = isdpkgvuln( pkg: "postfix", ver: "2.2.10-1ubuntu0.3", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.10"){
	if(( res = isdpkgvuln( pkg: "postfix", ver: "2.7.1-1ubuntu0.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU8.04 LTS"){
	if(( res = isdpkgvuln( pkg: "postfix", ver: "2.5.1-2ubuntu1.3", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

