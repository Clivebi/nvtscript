if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843282" );
	script_version( "2021-09-17T08:01:48+0000" );
	script_tag( name: "last_modification", value: "2021-09-17 08:01:48 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-12 07:29:58 +0200 (Sat, 12 Aug 2017)" );
	script_cve_id( "CVE-2017-9800", "CVE-2016-2167", "CVE-2016-8734" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-20 22:15:00 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for subversion USN-3388-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'subversion'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Joern Schneeweisz discovered that Subversion
  did not properly handle host names in 'svn+<A HREF='ssh://'>ssh://</A>' URLs. A
  remote attacker could use this to construct a subversion repository that when
  accessed could run arbitrary code with the privileges of the user.
  (CVE-2017-9800) Daniel Shahaf and James McCoy discovered that Subversion did not
  properly verify realms when using Cyrus SASL authentication. A remote attacker
  could use this to possibly bypass intended access restrictions. This issue only
  affected Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2016-2167) Florian Weimer
  discovered that Subversion clients did not properly restrict XML entity
  expansion when accessing http(s):// URLs. A remote attacker could use this to
  cause a denial of service. This issue only affected Ubuntu 14.04 LTS and Ubuntu
  16.04 LTS. (CVE-2016-8734)" );
	script_tag( name: "affected", value: "subversion on Ubuntu 17.04,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3388-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3388-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|17\\.04|16\\.04 LTS)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libapache2-mod-svn", ver: "1.8.8-1ubuntu3.3", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libapache2-svn", ver: "1.8.8-1ubuntu3.3", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libsvn1:amd64", ver: "1.8.8-1ubuntu3.3", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libsvn1:i386", ver: "1.8.8-1ubuntu3.3", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "subversion", ver: "1.8.8-1ubuntu3.3", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.04"){
	if(( res = isdpkgvuln( pkg: "libsvn1:i386", ver: "1.9.5-1ubuntu1.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libsvn1:amd64", ver: "1.9.5-1ubuntu1.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "subversion", ver: "1.9.5-1ubuntu1.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libapache2-mod-svn", ver: "1.9.3-2ubuntu1.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libapache2-svn", ver: "1.9.3-2ubuntu1.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libsvn1:amd64", ver: "1.9.3-2ubuntu1.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libsvn1:i386", ver: "1.9.3-2ubuntu1.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "subversion", ver: "1.9.3-2ubuntu1.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

