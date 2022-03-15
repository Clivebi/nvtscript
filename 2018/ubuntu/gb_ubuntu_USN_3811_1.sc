if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843808" );
	script_version( "2021-06-03T11:00:21+0000" );
	script_cve_id( "CVE-2017-15705", "CVE-2018-11780", "CVE-2018-11781" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-03 11:00:21 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-06 21:15:00 +0000 (Tue, 06 Aug 2019)" );
	script_tag( name: "creation_date", value: "2018-11-07 06:02:32 +0100 (Wed, 07 Nov 2018)" );
	script_name( "Ubuntu Update for spamassassin USN-3811-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|18\\.04 LTS|16\\.04 LTS)" );
	script_xref( name: "USN", value: "3811-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3811-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for
the 'spamassassin' package(s) announced via the USN-3811-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version
is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that SpamAssassin incorrectly
handled certain unclosed tags in emails. A remote attacker could possibly use this
issue to cause a denial of service. (CVE-2017-15705)

It was discovered that SpamAssassin incorrectly handled the PDFInfo plugin.
A remote attacker could possibly use this issue to execute arbitrary code.
(CVE-2018-11780)

It was discovered that SpamAssassin incorrectly handled meta rule syntax. A
local attacker could possibly use this issue to execute arbitrary code.
(CVE-2018-11781)" );
	script_tag( name: "affected", value: "spamassassin on Ubuntu 18.04 LTS,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS." );
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
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "spamassassin", ver: "3.4.2-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU18.04 LTS"){
	if(( res = isdpkgvuln( pkg: "spamassassin", ver: "3.4.2-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "spamassassin", ver: "3.4.2-0ubuntu0.16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

