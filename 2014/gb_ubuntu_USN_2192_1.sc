if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841821" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-05-12 09:13:48 +0530 (Mon, 12 May 2014)" );
	script_cve_id( "CVE-2010-5298", "CVE-2014-0198" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_name( "Ubuntu Update for openssl USN-2192-1" );
	script_tag( name: "affected", value: "openssl on Ubuntu 14.04 LTS,
  Ubuntu 13.10,
  Ubuntu 12.10,
  Ubuntu 12.04 LTS" );
	script_tag( name: "insight", value: "It was discovered that OpenSSL incorrectly handled memory in
the ssl3_read_bytes() function. A remote attacker could use this issue to
possibly cause OpenSSL to crash, resulting in a denial of service.
(CVE-2010-5298)

It was discovered that OpenSSL incorrectly handled memory in the
do_ssl3_write() function. A remote attacker could use this issue to
possibly cause OpenSSL to crash, resulting in a denial of service.
(CVE-2014-0198)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2192-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2192-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssl'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|12\\.04 LTS|13\\.10|12\\.10)" );
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
	if(( res = isdpkgvuln( pkg: "libssl1.0.0:i386", ver: "1.0.1f-1ubuntu2.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libssl1.0.0", ver: "1.0.1-4ubuntu5.13", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.10"){
	if(( res = isdpkgvuln( pkg: "libssl1.0.0:i386", ver: "1.0.1e-3ubuntu1.3", rls: "UBUNTU13.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "libssl1.0.0", ver: "1.0.1c-3ubuntu2.8", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

