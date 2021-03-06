if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1144-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840674" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-06-10 16:29:51 +0200 (Fri, 10 Jun 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "USN", value: "1144-1" );
	script_cve_id( "CVE-2011-1752", "CVE-2011-1783", "CVE-2011-1921" );
	script_name( "Ubuntu Update for subversion USN-1144-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.10|10\\.04 LTS|11\\.04)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1144-1" );
	script_tag( name: "affected", value: "subversion on Ubuntu 11.04,
  Ubuntu 10.10,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Joe Schaefer discovered that the Subversion mod_dav_svn module for Apache
  did not properly handle certain baselined WebDAV resource requests. A
  remote attacker could use this flaw to cause the service to crash, leading
  to a denial of service. (CVE-2011-1752)

  Ivan Zhakov discovered that the Subversion mod_dav_svn module for Apache
  did not properly handle certain requests. A remote attacker could use this
  flaw to cause the service to consume all available resources, leading to a
  denial of service. (CVE-2011-1783)

  Kamesh Jayachandran discovered that the Subversion mod_dav_svn module for
  Apache did not properly handle access control in certain situations. A
  remote user could use this flaw to gain access to files that would
  otherwise be unreadable. (CVE-2011-1921)" );
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
	if(( res = isdpkgvuln( pkg: "libapache2-svn", ver: "1.6.12dfsg-1ubuntu1.3", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libapache2-svn", ver: "1.6.6dfsg-2ubuntu1.3", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "libapache2-svn", ver: "1.6.12dfsg-4ubuntu2.1", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

