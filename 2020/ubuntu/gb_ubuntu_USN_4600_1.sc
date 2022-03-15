if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844671" );
	script_version( "2021-07-12T02:00:56+0000" );
	script_cve_id( "CVE-2019-16869", "CVE-2019-20444", "CVE-2019-20445", "CVE-2020-7238" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-12 02:00:56 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-26 10:15:00 +0000 (Mon, 26 Apr 2021)" );
	script_tag( name: "creation_date", value: "2020-10-23 03:00:33 +0000 (Fri, 23 Oct 2020)" );
	script_name( "Ubuntu: Security Advisory for netty-3.9 (USN-4600-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.04 LTS" );
	script_xref( name: "USN", value: "4600-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-October/005713.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'netty-3.9'
  package(s) announced via the USN-4600-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Netty had HTTP request smuggling vulnerabilities. A
remote attacker could used it to extract sensitive information. (CVE-2019-16869,
CVE-2019-20444, CVE-2019-20445, CVE-2020-7238)" );
	script_tag( name: "affected", value: "'netty-3.9' package(s) on Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "libnetty-3.9-java", ver: "3.9.0.Final-1ubuntu0.1", rls: "UBUNTU16.04 LTS" ) )){
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

