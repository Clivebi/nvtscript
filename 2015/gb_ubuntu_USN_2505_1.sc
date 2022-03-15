if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842102" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-02-26 05:40:14 +0100 (Thu, 26 Feb 2015)" );
	script_cve_id( "CVE-2015-0819", "CVE-2015-0820", "CVE-2015-0821", "CVE-2015-0822", "CVE-2015-0823", "CVE-2015-0824", "CVE-2015-0825", "CVE-2015-0826", "CVE-2015-0827", "CVE-2015-0829", "CVE-2015-0830", "CVE-2015-0831", "CVE-2015-0832", "CVE-2015-0834", "CVE-2015-0835", "CVE-2015-0836" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for firefox USN-2505-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Matthew Noorenberghe discovered that
whitelisted Mozilla domains could make UITour API calls from background tabs. If
one of these domains were compromised and open in a background tab, an attacker
could potentially exploit this to conduct clickjacking attacks. (CVE-2015-0819)

Jan de Mooij discovered an issue that affects content using the Caja
Compiler. If web content loads specially crafted code, this could be used
to bypass sandboxing security measures provided by Caja. (CVE-2015-0820)

Armin Razmdjou discovered that opening hyperlinks with specific mouse
and key combinations could allow a Chrome privileged URL to be opened
without context restrictions being preserved. If a user were tricked in to
opening a specially crafted website, an attacker could potentially exploit
this to bypass security restrictions. (CVE-2015-0821)

Armin Razmdjou discovered that contents of locally readable files could
be made available via manipulation of form autocomplete in some
circumstances. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to obtain sensitive
information. (CVE-2015-0822)

Atte Kettunen discovered a use-after-free in the OpenType Sanitiser (OTS)
in some circumstances. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to cause a
denial of service via application crash. (CVE-2015-0823)

Atte Kettunen discovered a crash when drawing images using Cairo in some
circumstances. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial of
service. (CVE-2015-0824)

Atte Kettunen discovered a buffer underflow during playback of MP3 files
in some circumstances. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to obtain
sensitive information. (CVE-2015-0825)

Atte Kettunen discovered a buffer overflow during CSS restyling in some
circumstances. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial of
service via application crash, or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2015-0826)

Abhishek Arya discovered an out-of-bounds read and write when rendering
SVG content in some circumstances. If a user were tricked in to opening
a specially crafted website, an attacker could potentially exploit this
to obtain sensitive information. (CVE-2015-0827)

A buffer overflow was discovered in libstagefright during video p ...

  Description truncated, please see the referenced URL(s) for more information." );
	script_tag( name: "affected", value: "firefox on Ubuntu 14.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2505-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2505-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.10|14\\.04 LTS|12\\.04 LTS)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.10"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "36.0+build2-0ubuntu0.14.10.4", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "36.0+build2-0ubuntu0.14.04.4", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "36.0+build2-0ubuntu0.12.04.5", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

