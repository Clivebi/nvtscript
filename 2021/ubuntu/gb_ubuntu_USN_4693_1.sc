if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844787" );
	script_version( "2021-08-19T14:00:55+0000" );
	script_cve_id( "CVE-2019-12385", "CVE-2019-12386" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-19 14:00:55 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-11 16:15:00 +0000 (Mon, 11 Nov 2019)" );
	script_tag( name: "creation_date", value: "2021-01-16 04:00:25 +0000 (Sat, 16 Jan 2021)" );
	script_name( "Ubuntu: Security Advisory for ampache (USN-4693-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.04 LTS" );
	script_xref( name: "USN", value: "4693-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-January/005841.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ampache'
  package(s) announced via the USN-4693-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that an SQL injection vulnerability exists in the Ampache
search engine. Any user able to perform searches could dump any data contained
in the database. An attacker could use this to disclose sensitive information.
(CVE-2019-12385)

It was discovered that an XSS vulnerability in Ampache. An attacker could use
this vulnerability to force an admin to create a new privileged user.
(CVE-2019-12386)" );
	script_tag( name: "affected", value: "'ampache' package(s) on Ubuntu 16.04 LTS." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "UBUNTU16.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "ampache", ver: "3.6-rzb2779+dfsg-0ubuntu9.2", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "ampache-common", ver: "3.6-rzb2779+dfsg-0ubuntu9.2", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

