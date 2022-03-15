if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842641" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-02-16 06:28:24 +0100 (Tue, 16 Feb 2016)" );
	script_cve_id( "CVE-2015-8803", "CVE-2015-8804", "CVE-2015-8805" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for nettle USN-2897-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nettle'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Hanno B&#246 ck discovered that Nettle
  incorrectly handled carry propagation in the NIST P-256 elliptic curve.
  (CVE-2015-8803)

  Hanno B&#246 ck discovered that Nettle incorrectly handled carry propagation in
  the NIST P-384 elliptic curve. (CVE-2015-8804)

  Niels Moeller discovered that Nettle incorrectly handled carry propagation
  in the NIST P-256 elliptic curve. (CVE-2015-8805)" );
	script_tag( name: "affected", value: "nettle on Ubuntu 15.10,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2897-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2897-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|15\\.10)" );
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
	if(( res = isdpkgvuln( pkg: "libnettle4:i386", ver: "2.7.1-1ubuntu0.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libnettle4:amd64", ver: "2.7.1-1ubuntu0.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU15.10"){
	if(( res = isdpkgvuln( pkg: "libnettle6:i386", ver: "3.1.1-4ubuntu0.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libnettle6:amd64", ver: "3.1.1-4ubuntu0.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

