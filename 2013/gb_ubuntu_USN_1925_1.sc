if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841519" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-08-08 11:46:46 +0530 (Thu, 08 Aug 2013)" );
	script_cve_id( "CVE-2013-1701", "CVE-2013-1709", "CVE-2013-1710", "CVE-2013-1713", "CVE-2013-1714", "CVE-2013-1717" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Ubuntu Update for thunderbird USN-1925-1" );
	script_tag( name: "affected", value: "thunderbird on Ubuntu 13.04,
  Ubuntu 12.10,
  Ubuntu 12.04 LTS" );
	script_tag( name: "insight", value: "Jeff Gilbert and Henrik Skupin discovered multiple memory safety issues
in Thunderbird. If the user were tricked in to opening a specially crafted
message with scripting enabled, an attacker could possibly exploit these
to cause a denial of service via application crash, or potentially execute
arbitrary code with the privileges of the user invoking Thunderbird.
(CVE-2013-1701)

It was discovered that a document's URI could be set to the URI of
a different document. If a user had scripting enabled, an attacker
could potentially exploit this to conduct cross-site scripting (XSS)
attacks. (CVE-2013-1709)

A flaw was discovered when generating a CRMF request in certain
circumstances. If a user had scripting enabled, an attacker could
potentially exploit this to conduct cross-site scripting (XSS) attacks,
or execute arbitrary code with the privileges of the user invoking
Thunderbird. (CVE-2013-1710)

Cody Crews discovered that some Javascript components performed security
checks against the wrong URI, potentially bypassing same-origin policy
restrictions. If a user had scripting enabled, an attacker could exploit
this to conduct cross-site scripting (XSS) attacks or install addons
from a malicious site. (CVE-2013-1713)

Federico Lanusse discovered that web workers could bypass cross-origin
checks when using XMLHttpRequest. If a user had scripting enabled, an
attacker could potentially exploit this to conduct cross-site scripting
(XSS) attacks. (CVE-2013-1714)

Georgi Guninski and John Schoenick discovered that Java applets could
access local files under certain circumstances. If a user had scripting
enabled, an attacker could potentially exploit this to steal confidential
data. (CVE-2013-1717)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "1925-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1925-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|12\\.10|13\\.04)" );
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
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "17.0.8+build1-0ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "17.0.8+build1-0ubuntu0.12.10.1", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.04"){
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "17.0.8+build1-0ubuntu0.13.04.1", rls: "UBUNTU13.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

