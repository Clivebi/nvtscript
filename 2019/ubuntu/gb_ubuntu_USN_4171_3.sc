if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844222" );
	script_version( "2021-08-31T10:01:32+0000" );
	script_cve_id( "CVE-2019-11481", "CVE-2019-11482", "CVE-2019-11483", "CVE-2019-11485", "CVE-2019-15790" );
	script_tag( name: "cvss_base", value: "6.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 10:01:32 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-12 21:21:00 +0000 (Wed, 12 Feb 2020)" );
	script_tag( name: "creation_date", value: "2019-11-06 03:01:19 +0000 (Wed, 06 Nov 2019)" );
	script_name( "Ubuntu Update for apport USN-4171-3" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU19\\.10|UBUNTU19\\.04|UBUNTU16\\.04 LTS)" );
	script_xref( name: "USN", value: "4171-3" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-November/005180.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'apport'
  package(s) announced via the USN-4171-3 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "USN-4171-1 fixed vulnerabilities in Apport. The update caused a regression
in the Python Apport library. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

Kevin Backhouse discovered Apport would read its user-controlled settings
file as the root user. This could be used by a local attacker to possibly
crash Apport or have other unspecified consequences. (CVE-2019-11481)

Sander Bos discovered a race-condition in Apport during core dump
creation. This could be used by a local attacker to generate a crash report
for a privileged process that is readable by an unprivileged user.
(CVE-2019-11482)

Sander Bos discovered Apport mishandled crash dumps originating from
containers. This could be used by a local attacker to generate a crash
report for a privileged process that is readable by an unprivileged user.
(CVE-2019-11483)

Sander Bos discovered Apport mishandled lock-file creation. This could be
used by a local attacker to cause a denial of service against Apport.
(CVE-2019-11485)

Kevin Backhouse discovered Apport read various process-specific files with
elevated privileges during crash dump generation. This could could be used
by a local attacker to generate a crash report for a privileged process
that is readable by an unprivileged user. (CVE-2019-15790)" );
	script_tag( name: "affected", value: "'apport' package(s) on Ubuntu 19.10, Ubuntu 19.04, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "apport", ver: "2.20.9-0ubuntu7.9", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "python-apport", ver: "2.20.9-0ubuntu7.9", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "python3-apport", ver: "2.20.9-0ubuntu7.9", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "apport", ver: "2.20.11-0ubuntu8.2", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "python-apport", ver: "2.20.11-0ubuntu8.2", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "python3-apport", ver: "2.20.11-0ubuntu8.2", rls: "UBUNTU19.10" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "apport", ver: "2.20.10-0ubuntu27.3", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "python-apport", ver: "2.20.10-0ubuntu27.3", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "python3-apport", ver: "2.20.10-0ubuntu27.3", rls: "UBUNTU19.04" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "apport", ver: "2.20.1-0ubuntu2.21", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "python-apport", ver: "2.20.1-0ubuntu2.21", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "python3-apport", ver: "2.20.1-0ubuntu2.21", rls: "UBUNTU16.04 LTS" ) )){
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

