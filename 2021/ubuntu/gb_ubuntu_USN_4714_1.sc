if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844807" );
	script_version( "2021-08-19T14:00:55+0000" );
	script_cve_id( "CVE-2020-26217", "CVE-2020-26258", "CVE-2020-26259" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-19 14:00:55 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-01-29 04:00:38 +0000 (Fri, 29 Jan 2021)" );
	script_name( "Ubuntu: Security Advisory for libxstream-java (USN-4714-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU20\\.04 LTS)" );
	script_xref( name: "Advisory-ID", value: "USN-4714-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-January/005865.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libxstream-java'
  package(s) announced via the USN-4714-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Zhihong Tian and Hui Lu found that XStream was vulnerable to remote code
execution. A remote attacker could run arbitrary shell commands by
manipulating the processed input stream. (CVE-2020-26217)

It was discovered that XStream was vulnerable to server-side forgery attacks.
A remote attacker could request data from internal resources that are not
publicly available only by manipulating the processed input stream.
(CVE-2020-26258)

It was discovered that XStream was vulnerable to arbitrary file deletion on
the local host. A remote attacker could use this to delete arbitrary known
files on the host as long as the executing process had sufficient rights only
by manipulating the processed input stream. (CVE-2020-26259)" );
	script_tag( name: "affected", value: "'libxstream-java' package(s) on Ubuntu 20.04 LTS, Ubuntu 18.04 LTS." );
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
if(release == "UBUNTU18.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "libxstream-java", ver: "1.4.11.1-1~18.04.1", rls: "UBUNTU18.04 LTS" ) )){
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
if(release == "UBUNTU20.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "libxstream-java", ver: "1.4.11.1-1ubuntu0.1", rls: "UBUNTU20.04 LTS" ) )){
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

