if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841966" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-09-12 05:57:44 +0200 (Fri, 12 Sep 2014)" );
	script_cve_id( "CVE-2014-1553", "CVE-2014-1562", "CVE-2014-1563", "CVE-2014-1564", "CVE-2014-1565", "CVE-2014-1567" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Ubuntu Update for thunderbird USN-2330-1" );
	script_tag( name: "insight", value: "Jan de Mooij, Christian Holler, Karl
Tomlinson, Randell Jesup, Gary Kwong, Jesse Ruderman and JW Wang discovered
multiple memory safety issues in Thunderbird. If a user were tricked in to
opening a specially crafted message with scripting enabled, an attacker could
potentially exploit these to cause a denial of service via application crash,
or execute arbitrary code with the privileges of the user invoking Thunderbird.
(CVE-2014-1553, CVE-2014-1562)

Abhishek Arya discovered a use-after-free during DOM interactions with
SVG. If a user were tricked in to opening a specially crafted message
with scripting enabled, an attacker could potentially exploit this to
cause a denial of service via application crash or execute arbitrary code
with the privileges of the user invoking Thunderbird. (CVE-2014-1563)

Michal Zalewski discovered that memory is not initialized properly during
GIF rendering in some circumstances. If a user were tricked in to opening
a specially crafted message, an attacker could potentially exploit this to
steal confidential information. (CVE-2014-1564)

Holger Fuhrmannek discovered an out-of-bounds read in Web Audio. If a
user were tricked in to opening a specially crafted message with scripting
enabled, an attacker could potentially exploit this to cause a denial of
service via application crash or steal confidential information.
(CVE-2014-1565)

A use-after-free was discovered during text layout in some circumstances.
If a user were tricked in to opening a specially crafted message with
scripting enabled, an attacker could potentially exploit this to cause a
denial of service via application crash or execute arbitrary code with
the privileges of the user invoking Thunderbird. (CVE-2014-1567)" );
	script_tag( name: "affected", value: "thunderbird on Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2330-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2330-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|12\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "1:31.1.1+build1-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "1:31.1.1+build1-0ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

