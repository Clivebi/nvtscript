if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844429" );
	script_version( "2020-05-15T04:25:55+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-05-15 04:25:55 +0000 (Fri, 15 May 2020)" );
	script_tag( name: "creation_date", value: "2020-05-14 03:00:30 +0000 (Thu, 14 May 2020)" );
	script_name( "Ubuntu: Security Advisory for file (USN-3911-2)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS)" );
	script_xref( name: "USN", value: "3911-2" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-May/005429.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'file'
  package(s) announced via the USN-3911-2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "USN-3911-1 fixed vulnerabilities in file. One of the backported security
fixes introduced a regression that caused the interpreter string to be
truncated. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

It was discovered that file incorrectly handled certain malformed ELF
files. An attacker could use this issue to cause a denial of service, or
possibly execute arbitrary code." );
	script_tag( name: "affected", value: "'file' package(s) on Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "file", ver: "1:5.32-2ubuntu0.4", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libmagic1", ver: "1:5.32-2ubuntu0.4", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "file", ver: "1:5.25-2ubuntu1.4", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libmagic1", ver: "1:5.25-2ubuntu1.4", rls: "UBUNTU16.04 LTS" ) )){
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

