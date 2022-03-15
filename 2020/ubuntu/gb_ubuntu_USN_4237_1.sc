if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844292" );
	script_version( "2021-07-12T02:00:56+0000" );
	script_cve_id( "CVE-2018-11805", "CVE-2019-12420" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-07-12 02:00:56 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-13 19:15:00 +0000 (Mon, 13 Jan 2020)" );
	script_tag( name: "creation_date", value: "2020-01-14 04:01:00 +0000 (Tue, 14 Jan 2020)" );
	script_name( "Ubuntu Update for spamassassin USN-4237-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU19\\.10|UBUNTU19\\.04|UBUNTU16\\.04 LTS)" );
	script_xref( name: "USN", value: "4237-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-January/005266.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'spamassassin'
  package(s) announced via the USN-4237-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that SpamAssassin incorrectly handled certain CF files.
If a user or automated system were tricked into using a specially-crafted
CF file, a remote attacker could possibly run arbitrary code.
(CVE-2018-11805)

It was discovered that SpamAssassin incorrectly handled certain messages.
A remote attacker could possibly use this issue to cause SpamAssassin to
consume resources, resulting in a denial of service. (CVE-2019-12420)" );
	script_tag( name: "affected", value: "'spamassassin' package(s) on Ubuntu 19.10, Ubuntu 19.04, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "spamassassin", ver: "3.4.2-0ubuntu0.18.04.2", rls: "UBUNTU18.04 LTS" ) )){
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
if(release == "UBUNTU19.10"){
	if(!isnull( res = isdpkgvuln( pkg: "spamassassin", ver: "3.4.2-1ubuntu0.19.10.1", rls: "UBUNTU19.10" ) )){
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
if(release == "UBUNTU19.04"){
	if(!isnull( res = isdpkgvuln( pkg: "spamassassin", ver: "3.4.2-1ubuntu0.19.04.1", rls: "UBUNTU19.04" ) )){
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
if(release == "UBUNTU16.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "spamassassin", ver: "3.4.2-0ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) )){
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

