if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842518" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-11-06 06:02:42 +0100 (Fri, 06 Nov 2015)" );
	script_cve_id( "CVE-2015-4551", "CVE-2015-5212", "CVE-2015-5213", "CVE-2015-5214" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for libreoffice USN-2793-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libreoffice'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Federico Scrinzi discovered that LibreOffice
incorrectly handled documents inserted into Writer or Calc via links. If a user
were tricked into opening a specially crafted document, a remote attacker could
possibly obtain the contents of arbitrary files. (CVE-2015-4551)

It was discovered that LibreOffice incorrectly handled PrinterSetup data
stored in ODF files. If a user were tricked into opening a specially
crafted ODF document, a remote attacker could cause LibreOffice to crash,
and possibly execute arbitrary code. (CVE-2015-5212)

It was discovered that LibreOffice incorrectly handled the number of pieces
in DOC files. If a user were tricked into opening a specially crafted DOC
document, a remote attacker could cause LibreOffice to crash, and possibly
execute arbitrary code. (CVE-2015-5213)

It was discovered that LibreOffice incorrectly handled bookmarks in DOC
files. If a user were tricked into opening a specially crafted DOC
document, a remote attacker could cause LibreOffice to crash, and possibly
execute arbitrary code. (CVE-2015-5214)" );
	script_tag( name: "affected", value: "libreoffice on Ubuntu 15.04,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2793-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2793-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(15\\.04|14\\.04 LTS|12\\.04 LTS)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU15.04"){
	if(( res = isdpkgvuln( pkg: "libreoffice-core", ver: "1:4.4.6~rc3-0ubuntu1", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libreoffice-core", ver: "1:4.2.8-0ubuntu3", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libreoffice-core", ver: "1:3.5.7-0ubuntu9", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

