if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842155" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-04-03 05:09:52 +0200 (Fri, 03 Apr 2015)" );
	script_cve_id( "CVE-2015-0801", "CVE-2015-0807", "CVE-2015-0813", "CVE-2015-0815", "CVE-2015-0816" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for thunderbird USN-2552-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Olli Pettay and Boris Zbarsky discovered an
issue during anchor navigations in some circumstances. If a user were tricked in
to opening a specially crafted message with scripting enabled, an attacker could
potentially exploit this to bypass same-origin policy restrictions.
(CVE-2015-0801)

Christoph Kerschbaumer discovered that CORS requests from
navigator.sendBeacon() followed 30x redirections after preflight. If a
user were tricked in to opening a specially crafted message with
scripting enabled, an attacker could potentially exploit this to conduct
cross-site request forgery (XSRF) attacks. (CVE-2015-0807)

Aki Helin discovered a use-after-free when playing MP3 audio files using
the Fluendo MP3 GStreamer plugin in certain circumstances. If a user were
tricked in to opening a specially crafted message, an attacker could
potentially exploit this to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user invoking
Thunderbird. (CVE-2015-0813)

Christian Holler, Steve Fink, and Byron Campen discovered multiple memory
safety issues in Thunderbird. If a user were tricked in to opening a
specially crafted message with scripting enabled, an attacker could
potentially exploit these to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user invoking
Thunderbird. (CVE-2015-0815)

Mariusz Mlynski discovered that documents loaded via resource: URLs (such
as PDF.js) could load privileged chrome pages. If a user were tricked in
to opening a specially crafted message with scripting enabled, an attacker
could potentially exploit this in combination with another flaw, in order
to execute arbitrary script in a privileged context. (CVE-2015-0816)" );
	script_tag( name: "affected", value: "thunderbird on Ubuntu 14.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2552-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2552-1/" );
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
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "1:31.6.0+build1-0ubuntu0.14.10.1", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "1:31.6.0+build1-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "1:31.6.0+build1-0ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

