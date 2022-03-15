if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844950" );
	script_version( "2021-05-25T12:16:58+0000" );
	script_cve_id( "CVE-2021-20095" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-05-25 12:16:58 +0000 (Tue, 25 May 2021)" );
	script_tag( name: "creation_date", value: "2021-05-20 04:46:49 +0000 (Thu, 20 May 2021)" );
	script_name( "Ubuntu: Security Advisory for python-babel (USN-4962-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU20\\.04 LTS|UBUNTU18\\.04 LTS|UBUNTU20\\.10)" );
	script_xref( name: "Advisory-ID", value: "USN-4962-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-May/006036.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-babel'
  package(s) announced via the USN-4962-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Babel incorrectly handled certain inputs.
An attacker could possibly use this issue to execute arbitrary code." );
	script_tag( name: "affected", value: "'python-babel' package(s) on Ubuntu 20.10, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "python-babel", ver: "2.6.0+dfsg.1-1ubuntu2.2", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "python-babel-localedata", ver: "2.6.0+dfsg.1-1ubuntu2.2", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "python3-babel", ver: "2.6.0+dfsg.1-1ubuntu2.2", rls: "UBUNTU20.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "python-babel", ver: "2.4.0+dfsg.1-2ubuntu1.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "python-babel-localedata", ver: "2.4.0+dfsg.1-2ubuntu1.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "python3-babel", ver: "2.4.0+dfsg.1-2ubuntu1.1", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "python-babel-localedata", ver: "2.8.0+dfsg.1-4ubuntu0.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "python3-babel", ver: "2.8.0+dfsg.1-4ubuntu0.1", rls: "UBUNTU20.10" ) )){
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

