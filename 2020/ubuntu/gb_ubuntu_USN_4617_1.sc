if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844696" );
	script_version( "2021-07-09T11:00:55+0000" );
	script_cve_id( "CVE-2020-25650", "CVE-2020-25651", "CVE-2020-25652", "CVE-2020-25653" );
	script_tag( name: "cvss_base", value: "5.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-07-09 11:00:55 +0000 (Fri, 09 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-19 17:38:00 +0000 (Fri, 19 Feb 2021)" );
	script_tag( name: "creation_date", value: "2020-11-05 04:00:56 +0000 (Thu, 05 Nov 2020)" );
	script_name( "Ubuntu: Security Advisory for spice-vdagent (USN-4617-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU20\\.04 LTS|UBUNTU18\\.04 LTS|UBUNTU20\\.10)" );
	script_xref( name: "USN", value: "4617-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-November/005740.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'spice-vdagent'
  package(s) announced via the USN-4617-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Matthias Gerstner discovered that SPICE vdagent incorrectly handled the
active_xfers hash table. A local attacker could possibly use this issue to
cause SPICE vdagent to consume memory, resulting in a denial of service.
(CVE-2020-25650)

Matthias Gerstner discovered that SPICE vdagent incorrectly handled the
active_xfers hash table. A local attacker could possibly use this issue to
cause SPICE vdagent to consume memory, resulting in a denial of service, or
obtain sensitive file contents. (CVE-2020-25651)

Matthias Gerstner discovered that SPICE vdagent incorrectly handled a large
number of client connections. A local attacker could possibly use this
issue to cause SPICE vdagent to consume resources, resulting in a denial of
service. (CVE-2020-25652)

Matthias Gerstner discovered that SPICE vdagent incorrectly handled client
connections. A local attacker could possibly use this issue to obtain
sensitive information, paste clipboard contents, and transfer files into
the active session. (CVE-2020-25653)" );
	script_tag( name: "affected", value: "'spice-vdagent' package(s) on Ubuntu 20.10, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS." );
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
if(release == "UBUNTU20.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "spice-vdagent", ver: "0.19.0-2ubuntu0.2", rls: "UBUNTU20.04 LTS" ) )){
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
if(release == "UBUNTU18.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "spice-vdagent", ver: "0.17.0-1ubuntu2.2", rls: "UBUNTU18.04 LTS" ) )){
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
if(release == "UBUNTU20.10"){
	if(!isnull( res = isdpkgvuln( pkg: "spice-vdagent", ver: "0.20.0-1ubuntu0.1", rls: "UBUNTU20.10" ) )){
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

