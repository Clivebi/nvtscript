if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841937" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-08-21 10:09:53 +0200 (Thu, 21 Aug 2014)" );
	script_cve_id( "CVE-2014-3165", "CVE-2014-3166", "CVE-2014-3167" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Ubuntu Update for oxide-qt USN-2320-1" );
	script_tag( name: "affected", value: "oxide-qt on Ubuntu 14.04 LTS" );
	script_tag( name: "insight", value: "A use-after-free was discovered in the websockets
implementation in Blink. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to cause a denial
of service via renderer crash. (CVE-2014-3165)

An issue was discovered in the Public Key Pinning implementation in
Chromium. An attacker could potentially exploit this to obtain sensitive
information. (CVE-2014-3166)

Multiple security issues were discovered in Chromium. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service via application
crash or execute arbitrary code with the privileges of the user invoking
the program. (CVE-2014-3167)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2320-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2320-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'oxide-qt'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU14\\.04 LTS" );
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
	if(( res = isdpkgvuln( pkg: "liboxideqtcore0:i386", ver: "1.0.5-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "oxideqt-codecs:i386", ver: "1.0.5-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "oxideqt-codecs-extra:i386", ver: "1.0.5-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

