if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1712-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841294" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-01-31 09:26:22 +0530 (Thu, 31 Jan 2013)" );
	script_cve_id( "CVE-2012-5656", "CVE-2012-6076" );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "USN", value: "1712-1" );
	script_name( "Ubuntu Update for inkscape USN-1712-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'inkscape'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|11\\.10|10\\.04 LTS|12\\.10)" );
	script_tag( name: "affected", value: "inkscape on Ubuntu 12.10,
  Ubuntu 12.04 LTS,
  Ubuntu 11.10,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discoverd that Inkscape incorrectly handled XML external entities in
  SVG files. If a user were tricked into opening a specially-crafted SVG
  file, Inkscape could possibly include external files in drawings, resulting
  in information disclosure. (CVE-2012-5656)

  It was discovered that Inkscape attempted to open certain files from the
  /tmp directory instead of the current directory. A local attacker could
  trick a user into opening a different file than the one that was intended.
  This issue only applied to Ubuntu 11.10, Ubuntu 12.04 LTS and Ubuntu 12.10.
  (CVE-2012-6076)" );
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
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "inkscape", ver: "0.48.3.1-1ubuntu1.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "inkscape", ver: "0.48.2-0ubuntu1.1", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "inkscape", ver: "0.47.0-2ubuntu2.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "inkscape", ver: "0.48.3.1-1ubuntu6.1", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

