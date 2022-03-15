if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844731" );
	script_version( "2021-07-09T11:00:55+0000" );
	script_cve_id( "CVE-2020-15683", "CVE-2020-15969", "CVE-2020-16012", "CVE-2020-26950", "CVE-2020-26951", "CVE-2020-26953", "CVE-2020-26956", "CVE-2020-26958", "CVE-2020-26959", "CVE-2020-26960", "CVE-2020-26961", "CVE-2020-26965", "CVE-2020-26968" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-07-09 11:00:55 +0000 (Fri, 09 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-09 19:42:00 +0000 (Wed, 09 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-11-26 04:00:30 +0000 (Thu, 26 Nov 2020)" );
	script_name( "Ubuntu: Security Advisory for thunderbird (USN-4647-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU20\\.10" );
	script_xref( name: "USN", value: "4647-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-November/005778.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'thunderbird'
  package(s) announced via the USN-4647-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple security issues were discovered in Thunderbird. If a user were
tricked in to opening a specially crafted website in a browsing context,
an attacker could potentially exploit these to cause a denial of service,
obtain sensitive information across origins, bypass security restrictions,
conduct phishing attacks, conduct cross-site scripting (XSS) attacks,
bypass Content Security Policy (CSP) restrictions, conduct DNS rebinding
attacks, or execute arbitrary code." );
	script_tag( name: "affected", value: "'thunderbird' package(s) on Ubuntu 20.10." );
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
if(release == "UBUNTU20.10"){
	if(!isnull( res = isdpkgvuln( pkg: "thunderbird", ver: "1:78.5.0+build3-0ubuntu0.20.10.1", rls: "UBUNTU20.10" ) )){
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

