if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843659" );
	script_version( "2021-06-04T02:00:20+0000" );
	script_tag( name: "last_modification", value: "2021-06-04 02:00:20 +0000 (Fri, 04 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-10-16 06:20:47 +0200 (Tue, 16 Oct 2018)" );
	script_cve_id( "CVE-2018-12376", "CVE-2018-12377", "CVE-2018-12378", "CVE-2018-12383", "CVE-2018-12385" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-12-06 15:50:00 +0000 (Thu, 06 Dec 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for thunderbird USN-3793-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple security issues were discovered in Thunderbird. If a user were
tricked in to opening a specially crafted website in a browsing context,
an attacker could potentially exploit these to cause a denial of service,
or execute arbitrary code. (CVE-2018-12376, CVE-2018-12377,
CVE-2018-12378)

It was discovered that if a user saved passwords before Thunderbird 58 and
then later set a master password, an unencrypted copy of these passwords
would still be accessible. A local user could exploit this to obtain
sensitive information. (CVE-2018-12383)

A crash was discovered in TransportSecurityInfo used for SSL, which could
be triggered by data stored in the local cache directory. An attacker
could potentially exploit this in combination with another vulnerability
that allowed them to write data to the cache, to execute arbitrary code.
(CVE-2018-12385)" );
	script_tag( name: "affected", value: "thunderbird on Ubuntu 18.04 LTS,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "USN", value: "3793-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3793-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|18\\.04 LTS|16\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "1:60.2.1+build1-0ubuntu0.14.04.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU18.04 LTS"){
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "1:60.2.1+build1-0ubuntu0.18.04.2", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "1:60.2.1+build1-0ubuntu0.16.04.4", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

