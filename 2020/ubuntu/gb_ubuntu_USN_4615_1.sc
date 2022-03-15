if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844692" );
	script_version( "2021-07-12T11:00:45+0000" );
	script_cve_id( "CVE-2017-6298", "CVE-2017-6299", "CVE-2017-6300", "CVE-2017-6301", "CVE-2017-6302", "CVE-2017-6303", "CVE-2017-6304", "CVE-2017-6305", "CVE-2017-6306", "CVE-2017-6800", "CVE-2017-6801", "CVE-2017-6802" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-12 11:00:45 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-18 03:29:00 +0000 (Sat, 18 May 2019)" );
	script_tag( name: "creation_date", value: "2020-11-04 04:00:30 +0000 (Wed, 04 Nov 2020)" );
	script_name( "Ubuntu: Security Advisory for libytnef (USN-4615-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.04 LTS" );
	script_xref( name: "USN", value: "4615-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-November/005739.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libytnef'
  package(s) announced via the USN-4615-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Yerase's TNEF had null pointer dereferences, infinite
loop, buffer overflow, out of bounds reads, directory traversal issues and
other vulnerabilities. An attacker could use those issues to cause a crash
and consequently a denial of service. (CVE-2017-6298, CVE-2017-6299,
CVE-2017-6300, CVE-2017-6301, CVE-2017-6302, CVE-2017-6303, CVE-2017-6304,
CVE-2017-6305, CVE-2017-6306, CVE-2017-6800, CVE-2017-6801, CVE-2017-6802)" );
	script_tag( name: "affected", value: "'libytnef' package(s) on Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "libytnef0", ver: "1.5-9ubuntu0.1", rls: "UBUNTU16.04 LTS" ) )){
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

